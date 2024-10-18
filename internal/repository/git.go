package repository

import (
	"context"
	"fmt"
	"io/ioutil"
	stdhttp "net/http"
	"strings"
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
	logrus.Debugf("Looking for remote branch: %s", remoteBranch)

	remoteHeadRef, err := r.Repository.Reference(
		plumbing.ReferenceName(remoteBranch),
		true)
	if err != nil {
		logrus.Debugf("Failed to find reference for %s: %v", remoteBranch, err)
		return nil
	}
	if remoteHeadRef == nil {
		logrus.Debugf("No reference found for %s", remoteBranch)
		return nil
	}

	commitId := remoteHeadRef.Hash()
	if commitId.IsZero() {
		logrus.Debug("Found zero hash for remote branch")
		return nil
	}

	logrus.Debugf("Found commit hash %s for remote branch %s", commitId.String(), remoteBranch)
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
	// Validate hash before attempting reset
	if newHead.IsZero() {
		return fmt.Errorf("cannot reset to zero hash, no valid commit selected")
	}

	w, err := r.Repository.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// First verify the commit exists
	_, err = r.Repository.CommitObject(newHead)
	if err != nil {
		return fmt.Errorf("commit %s not found in repository: %w", newHead.String(), err)
	}

	err = w.Checkout(&git.CheckoutOptions{
		Hash:  newHead,
		Force: true,
	})
	if err != nil {
		return fmt.Errorf("git reset --hard %s failed: %w", newHead.String(), err)
	}

	logrus.Debugf("Successfully reset to commit %s", newHead.String())
	return nil
}

func isValidCommitHash(hash string) bool {
	if len(hash) != 40 {
		return false
	}
	// Check if string is valid hex
	for _, c := range hash {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// fetch fetches the config.Remote
func fetch(r repository, remote types.Remote) error {
	logrus.Debugf("Starting fetch for remote '%s' (URL: %s)", remote.Name, remote.URL)

	// Validate remote configuration
	if remote.URL == "" {
		return fmt.Errorf("empty URL for remote '%s'", remote.Name)
	}

	fetchOptions := git.FetchOptions{
		RemoteName: remote.Name,
		Force:      true,
		RefSpecs:   []gitConfig.RefSpec{"+refs/heads/*:refs/remotes/origin/*"},
		Progress:   nil,
		Tags:       git.AllTags,
	}

	if remote.Auth.AccessToken != "" {
		logrus.Debugf("Configuring GitHub authentication for remote '%s'", remote.Name)
		// For GitHub, the token should be used as the password with 'oauth2' as username
		fetchOptions.Auth = &http.BasicAuth{
			Username: "oauth2", // Changed from "comin" to "oauth2" for GitHub
			Password: remote.Auth.AccessToken,
		}

		// Add debug information about token format
		tokenLength := len(remote.Auth.AccessToken)
		if tokenLength > 0 {
			logrus.Debugf("Token length: %d characters", tokenLength)
			logrus.Debugf("Token prefix (first 4 chars): %s", remote.Auth.AccessToken[:4])
		}
	} else {
		logrus.Debugf("No access token provided for remote '%s'", remote.Name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(remote.Timeout)*time.Second)
	defer cancel()

	err := r.Repository.FetchContext(ctx, &fetchOptions)

	switch {
	case err == nil:
		logrus.Infof("Successfully fetched from remote '%s'", remote.Name)
		return nil
	case err == git.NoErrAlreadyUpToDate:
		logrus.Debugf("Remote '%s' is already up to date", remote.Name)
		return nil
	case err != nil && err.Error() == "authentication required":
		details := fmt.Sprintf("URL: %s, Token Present: %v, Token Length: %d",
			remote.URL, remote.Auth.AccessToken != "", len(remote.Auth.AccessToken))
		logrus.Errorf("GitHub authentication failed. Details: %s", details)
		return fmt.Errorf("GitHub authentication failed for remote '%s'. Please verify: \n"+
			"1. Token is a valid GitHub Personal Access Token\n"+
			"2. Token has 'repo' scope permissions\n"+
			"3. Token is not expired", remote.Name)
	case err != nil && strings.Contains(err.Error(), "403"):
		logrus.Errorf("GitHub API rate limit or permission issue: %v", err)
		return fmt.Errorf("GitHub access denied (403) for remote '%s'. Check token permissions", remote.Name)
	default:
		logrus.Errorf("Fetch error: %v", err)
		return fmt.Errorf("fetch from '%s' failed: %w", remote.Name, err)
	}
}

// Add this helper function to validate GitHub token format
func validateGitHubToken(token string) error {
	if len(token) != 40 { // GitHub tokens are typically 40 characters
		return fmt.Errorf("invalid token length: expected 40 characters, got %d", len(token))
	}

	// GitHub tokens are typically hexadecimal
	for _, c := range token {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return fmt.Errorf("token contains invalid characters (should be hexadecimal)")
		}
	}

	return nil
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

func checkGitHubAccess(remote types.Remote) error {
	if !strings.Contains(remote.URL, "github.com") {
		return nil
	}

	if err := validateGitHubToken(remote.Auth.AccessToken); err != nil {
		return fmt.Errorf("invalid token format: %w", err)
	}

	urlParts := strings.Split(strings.TrimSuffix(remote.URL, ".git"), "/")
	if len(urlParts) < 2 {
		return fmt.Errorf("invalid GitHub URL format")
	}

	owner := urlParts[len(urlParts)-2]
	repo := urlParts[len(urlParts)-1]

	client := &stdhttp.Client{Timeout: time.Second * 10} // using stdhttp.Client
	req, err := stdhttp.NewRequest(stdhttp.MethodGet,    // using stdhttp.NewRequest
		fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo),
		nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	if remote.Auth.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+remote.Auth.AccessToken)
		req.Header.Set("Accept", "application/vnd.github.v3+json")
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case stdhttp.StatusOK: // using stdhttp.StatusOK
		return nil
	case stdhttp.StatusUnauthorized: // using stdhttp.StatusUnauthorized
		return fmt.Errorf("unauthorized: invalid token")
	case stdhttp.StatusForbidden: // using stdhttp.StatusForbidden
		return fmt.Errorf("forbidden: token lacks required permissions")
	case stdhttp.StatusNotFound: // using stdhttp.StatusNotFound
		return fmt.Errorf("repository not found or no access")
	default:
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
}
