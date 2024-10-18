package repository

import (
	"context"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/go-git/go-git/v5"
	gitConfig "github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/nlewo/comin/internal/types"
	"github.com/sirupsen/logrus"
)

func RepositoryClone(directory, url, commitId, accessToken string) error {
	options := &git.CloneOptions{
		URL:        url,
		NoCheckout: true,
	}
	if accessToken != "" {
		options.Auth = &http.BasicAuth{
			Username: "comin",
			Password: accessToken,
		}
	}
	repository, err := git.PlainClone(directory, false, options)
	if err != nil {
		// return err
		return fmt.Errorf("Cannot clone the repository: %s", err)
	}
	worktree, err := repository.Worktree()
	if err != nil {
		// return err
		return fmt.Errorf("worktree Error: %s", err)
	}
	err = worktree.Checkout(&git.CheckoutOptions{
		Hash: plumbing.NewHash(commitId),
	})
	if err != nil {
		return fmt.Errorf("Cannot checkout the commit ID %s: '%s'", commitId, err)
	}
	return nil
}

func getRemoteCommitHash(r repository, remote, branch string) *plumbing.Hash {
	remoteBranch := fmt.Sprintf("refs/remotes/%s/%s", remote, branch)
	remoteHeadRef, err := r.Repository.Reference(
		plumbing.ReferenceName(remoteBranch),
		true)
	if err != nil {
		return nil
	}
	if remoteHeadRef == nil {
		return nil
	}
	commitId := remoteHeadRef.Hash()
	return &commitId
}

func hasNotBeenHardReset(r repository, branchName string, currentMainHash *plumbing.Hash, remoteMainHead *plumbing.Hash) error {
	if currentMainHash != nil && remoteMainHead != nil && *currentMainHash != *remoteMainHead {
		var ok bool
		ok, err := isAncestor(r.Repository, *currentMainHash, *remoteMainHead)
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("This branch has been hard reset: its head '%s' is not on top of '%s'",
				remoteMainHead.String(), currentMainHash.String())
		}
	}
	return nil
}

func getHeadFromRemoteAndBranch(r repository, remoteName, branchName, currentMainCommitId string) (newHead plumbing.Hash, msg string, err error) {
	var currentMainHash *plumbing.Hash
	head := getRemoteCommitHash(r, remoteName, branchName)
	if head == nil {
		return newHead, "", fmt.Errorf("The branch '%s/%s' doesn't exist", remoteName, branchName)
	}
	if currentMainCommitId != "" {
		c := plumbing.NewHash(currentMainCommitId)
		currentMainHash = &c
	}

	if err = hasNotBeenHardReset(r, branchName, currentMainHash, head); err != nil {
		return
	}

	commitObject, err := r.Repository.CommitObject(*head)
	if err != nil {
		return
	}

	return *head, commitObject.Message, nil
}

func hardReset(r repository, newHead plumbing.Hash) error {
	var w *git.Worktree
	w, err := r.Repository.Worktree()
	if err != nil {
		return fmt.Errorf("Failed to get the worktree")
	}
	err = w.Checkout(&git.CheckoutOptions{
		Hash:  newHead,
		Force: true,
	})
	if err != nil {
		return fmt.Errorf("git reset --hard %s fails: '%s'", newHead, err)
	}
	return nil
}

// fetch fetches the config.Remote
func fetch(r repository, remote types.Remote) error {
	logrus.Debugf("Fetching remote '%s'", remote.Name)
	logrus.Debugf("Starting fetch for remote configuration: %+v", remote)
	logrus.Debugf("Remote URL: %s", remote.URL)
	logrus.Debugf("Remote Name: %s", remote.Name)
	logrus.Debugf("Auth Config Present: %v", remote.Auth.AccessToken != "")
	fetchOptions := git.FetchOptions{
		RemoteName: remote.Name,
	}

	// Ensure auth token is properly set
	if remote.Auth.AccessToken != "" {
		logrus.Debugf("Setting up authentication for remote '%s'", remote.Name)
		fetchOptions.Auth = &http.BasicAuth{
			Username: "comin", // Or use a configured username
			Password: remote.Auth.AccessToken,
		}
	} else {
		logrus.Printf("No access token provided for remote '%s', authentication might fail", remote.Name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(remote.Timeout)*time.Second)
	defer cancel()

	err := r.Repository.FetchContext(ctx, &fetchOptions)

	// Better error handling
	switch {
	case err == nil:
		logrus.Infof("New commits have been fetched from '%s'", remote.URL)
		return nil
	case err == git.NoErrAlreadyUpToDate:
		logrus.Debugf("No new commits have been fetched from the remote '%s'", remote.Name)
		return nil
	case err.Error() == "authentication required":
		return fmt.Errorf("Authentication failed for remote '%s'. Please verify your access token", remote.Name)
	default:
		return fmt.Errorf("git fetch %s failed: %v", remote.Name, err)
	}
}

// isAncestor returns true when the commitId is an ancestor of the branch branchName
func isAncestor(r *git.Repository, base, top plumbing.Hash) (found bool, err error) {
	iter, err := r.Log(&git.LogOptions{From: top})
	if err != nil {
		return false, fmt.Errorf("git log %s fails: '%s'", top, err)
	}

	// To skip the first commit
	isFirst := true
	iter.ForEach(func(commit *object.Commit) error {
		if !isFirst && commit.Hash == base {
			found = true
			// This error is ignored and used to terminate early the loop :/
			return fmt.Errorf("base commit is ancestor of top commit")
		}
		isFirst = false
		return nil
	})
	return
}

func repositoryOpen(config types.GitConfig) (r *git.Repository, err error) {
	r, err = git.PlainInit(config.Path, false)
	if err != nil {
		r, err = git.PlainOpen(config.Path)
		if err != nil {
			return
		}
		logrus.Debugf("The local Git repository located at '%s' has been opened", config.Path)
	} else {
		logrus.Infof("The local Git repository located at '%s' has been initialized", config.Path)
	}
	return
}

func manageRemotes(r *git.Repository, remotes []types.Remote) error {
	for _, remote := range remotes {
		if err := manageRemote(r, remote); err != nil {
			return err
		}
	}
	return nil
}

func manageRemote(r *git.Repository, remote types.Remote) error {
	gitRemote, err := r.Remote(remote.Name)
	if err == git.ErrRemoteNotFound {
		logrus.Infof("Adding remote '%s' with url '%s'", remote.Name, remote.URL)
		_, err = r.CreateRemote(&gitConfig.RemoteConfig{
			Name: remote.Name,
			URLs: []string{remote.URL},
		})
		if err != nil {
			return err
		}
		return nil
	} else if err != nil {
		return err
	}

	remoteConfig := gitRemote.Config()
	if remoteConfig.URLs[0] != remote.URL {
		if err := r.DeleteRemote(remote.Name); err != nil {
			return err
		}
		logrus.Infof("Updating remote %s (%s)", remote.Name, remote.URL)
		_, err = r.CreateRemote(&gitConfig.RemoteConfig{
			Name: remote.Name,
			URLs: []string{remote.URL},
		})
		if err != nil {
			return err
		}
	}
	return nil
}

func verifyHead(r *git.Repository, config types.GitConfig) error {
	head, err := r.Head()
	if head == nil {
		return fmt.Errorf("Repository HEAD should not be nil")
	}
	logrus.Debugf("Repository HEAD is %s", head.Strings()[1])

	commit, err := r.CommitObject(head.Hash())
	if err != nil {
		return err
	}

	for _, keyPath := range config.GpgPublicKeyPaths {
		key, err := ioutil.ReadFile(keyPath)
		if err != nil {
			return err
		}
		entity, err := commit.Verify(string(key))
		if err != nil {
			logrus.Debug(err)
		} else {
			logrus.Debugf("Commit %s signed by %s", head.Hash(), entity.PrimaryIdentity().Name)
			return nil
		}

	}
	return fmt.Errorf("Commit %s is not signed", head.Hash())
}
