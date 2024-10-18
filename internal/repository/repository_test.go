package repository

//func TestNew(t *testing.T) {
//var err error
//r1Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//_, err = initRemoteRepostiory(r1Dir, true)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, err := New(gitConfig, "")
//assert.Nil(t, err)
//assert.Equal(t, "r1", r.RepositoryStatus.Remotes[0].Name)
//}

//func TestPreferMain(t *testing.T) {
//var err error
//r1Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//r1, err := initRemoteRepostiory(r1Dir, true)
//cMain := HeadCommitId(r1)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, err := New(gitConfig, "")
//assert.Nil(t, err)
//// r1/main: c1 - c2 - *c3
//// r1/testing: c1 - c2 - c3
//r.Fetch([]string{"r1"})
//err = r.Update()
//assert.Nil(t, err)
//assert.Equal(t, cMain, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3
//// r1/testing: c1 - c2 - c3 - *c4
//c4, err := commitFile(r1, r1Dir, "testing", "file-4")
//r.Fetch([]string{"r1"})
//err = r.Update()
//assert.Nil(t, err)
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3 - *c4
//// r1/testing: c1 - c2 - c3 - c4
//c4, err = commitFile(r1, r1Dir, "main", "file-4")
//r.Fetch([]string{"r1"})
//err = r.Update()
//assert.Nil(t, err)
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)
//}

//func TestMainCommitId(t *testing.T) {
//r1Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//r1, _ := initRemoteRepostiory(r1Dir, true)
//cMain := HeadCommitId(r1)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, cMain)

//// r1/main: c1 - c2 - c3 - c4
//// r1/testing: c1 - c2 - c3 - c4 - c5
//c4, _ := commitFile(r1, r1Dir, "main", "file-4")
//commitFile(r1, r1Dir, "testing", "file-4")
//c5, _ := commitFile(r1, r1Dir, "testing", "file-5")
//r.Fetch([]string{"r1"})
//r.Update()
//assert.Equal(t, c4, r.RepositoryStatus.MainCommitId)
//assert.Equal(t, c5, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)
//}

//func TestContinueIfHardReset(t *testing.T) {
//r1Dir := t.TempDir()
//r2Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//_, _ = initRemoteRepostiory(r1Dir, true)
//r2, _ := initRemoteRepostiory(r2Dir, true)
//cMain := HeadCommitId(r2)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//{
//Name: "r2",
//URL:  r2Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, cMain)

// r.Fetch([]string{"r1", "r2"})
// r.Update()

//// r1/main: c1 - c2 - ^c3
//// r1/testing: c1 - c2 - c3
//// r2/main: c1 - c2 - c3
//// r2/testing: c1 - c2 - c3 - *c4
//c4, _ := commitFile(r2, r2Dir, "testing", "file-4")
//r.Fetch([]string{"r1", "r2"})
//r.Update()
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3
//// r1/testing: c1 - c2 - c3
//// r2/main: c1 - c2 - c3 - *c4
//// r2/testing: c1 - c2 - c3 - ^c4
//c4, _ = commitFile(r2, r2Dir, "main", "file-4")
//r.Fetch([]string{"r1", "r2"})
//r.Update()
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.MainBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.MainRemoteName)
//}

// func TestMultipleRemote(t *testing.T) {
// var err error
// r1Dir := t.TempDir()
// r2Dir := t.TempDir()
// cominRepositoryDir := t.TempDir()
// r1, err := initRemoteRepostiory(r1Dir, true)
// r2, err := initRemoteRepostiory(r2Dir, true)
// assert.Nil(t, err)

//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//{
//Name: "r2",
//URL:  r2Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, err := New(gitConfig, "")
//assert.Nil(t, err)
//// r1/main: c1 - c2 - *c3
//// r2/main: c1 - c2 - c3
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, HeadCommitId(r.Repository), r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3 - *c4
//// r2/main: c1 - c2 - c3
//newCommitId, err := commitFile(r1, r1Dir, "main", "file-4")
//assert.Nil(t, err)
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3 - c4
//// r2/main: c1 - c2 - c3 - c4 - *c5
//commitFile(r2, r2Dir, "main", "file-4")
//newCommitId, err = commitFile(r2, r2Dir, "main", "file-5")
//assert.Nil(t, err)
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3 - c4 - *c5
//// r2/main: c1 - c2 - c3 - c4 - c5
//newCommitId, err = commitFile(r1, r1Dir, "main", "file-5")
//assert.Nil(t, err)
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/testing: c1 - c2 - c3 - c4 - c5 - c6 - *c7
//c6, _ := commitFile(r1, r1Dir, "main", "file-6")
//commitFile(r2, r2Dir, "main", "file-6")
//commitFile(r2, r2Dir, "testing", "file-4")
//commitFile(r2, r2Dir, "testing", "file-5")
//commitFile(r2, r2Dir, "testing", "file-6")
//c7, _ := commitFile(r2, r2Dir, "testing", "file-7")
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, c6, r.RepositoryStatus.MainCommitId)
//assert.Equal(t, c7, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/testing: c1 - c2 - c3 - c4 - c5 - c6 - *c7
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, c7, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)

//// TODO we should return the main commit ID in order to store it in the state
//// r1/main: c1 - c2 - c3 - c4 - c5 - c6 - *c8
//// r2/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/testing: c1 - c2 - c3 - c4 - c5 - c6 - c7
//c8, _ := commitFile(r1, r1Dir, "main", "file-8")
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, c8, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// Only fetch r2 remote
//// r1/main: c1 - c2 - c3 - c4 - c5 - c6 - *c8 - c9
//// r2/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/testing: c1 - c2 - c3 - c4 - c5 - c6 - c7
//c9, _ := commitFile(r1, r1Dir, "main", "file-9")
//r.Fetch([]string{"r2"})
//_ = r.Update()
//assert.Equal(t, c8, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

// assert.Equal(t, "r1", r.RepositoryStatus.Remotes[0].Name)
// assert.False(t, r.RepositoryStatus.Remotes[0].LastFetched)
// assert.Equal(t, "r2", r.RepositoryStatus.Remotes[1].Name)
// assert.True(t, r.RepositoryStatus.Remotes[1].LastFetched)

//// Fetch the r1 remote
//// r1/main: c1 - c2 - c3 - c4 - c5 - c6 - c8 - *c9
//// r2/main: c1 - c2 - c3 - c4 - c5 - c6
//// r2/testing: c1 - c2 - c3 - c4 - c5 - c6 - c7
//r.Fetch([]string{"r1"})
//_ = r.Update()
//assert.Equal(t, c9, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)
//}

//func TestTestingSwitch(t *testing.T) {
//r1Dir := t.TempDir()
//r2Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//_, _ = initRemoteRepostiory(r1Dir, true)
//r2, _ := initRemoteRepostiory(r2Dir, true)
//cMain := HeadCommitId(r2)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//{
//Name: "r2",
//URL:  r2Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, "")

//// r1/main: c1 - c2 - *c3
//// r1/testing: c1 - c2 - c3
//// r2/main: c1 - c2 - c3
//// r2/testing: c1 - c2 - c3
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, cMain, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3
//// r1/testing: c1 - c2 - c3
//// r2/main: c1 - c2 - c3
//// r2/testing: c1 - c2 - c3 - *c4
//c4, _ := commitFile(r2, r2Dir, "testing", "file-4")
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3
//// r1/testing: c1 - c2 - c3
//// r2/main: c1 - c2 - c3
//// r2/testing: c1 - c2 - c3 - *c4
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)

//// r1/main: c1 - c2 - c3
//// r1/testing: c1 - c2 - c3
//// r2/main: c1 - c2 - c3 - *c4
//// r2/testing: c1 - c2 - c3 - c4
//commitFile(r2, r2Dir, "main", "file-4")
//r.Fetch([]string{"r1", "r2"})
//_ = r.Update()
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r2", r.RepositoryStatus.SelectedRemoteName)
//}

//func TestWithoutTesting(t *testing.T) {
//var err error
//r1Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//_, err = initRemoteRepostiory(r1Dir, false)
//assert.Nil(t, err)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, "")

//r.Fetch([]string{"r1"})
//_ = r.Update()
//assert.Equal(t, HeadCommitId(r.Repository), r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)
//}

// func TestRepositoryUpdateMain(t *testing.T) {
// remoteRepositoryDir := t.TempDir()
// cominRepositoryDir := t.TempDir()
// remoteRepository, err := initRemoteRepostiory(remoteRepositoryDir, true)
// assert.Nil(t, err)

//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "origin",
//URL:  remoteRepositoryDir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, "")

//// The remote repository is initially checkouted
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, HeadCommitId(r.Repository), r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// Without any new remote commits, the local repository is not updated
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, HeadCommitId(r.Repository), r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// A new commit is pushed to the remote repository: the local
//// repository is updated
//newCommitId, err := commitFile(remoteRepository, remoteRepositoryDir, "main", "file-4")
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// A commit is pushed to the testing branch which is currently
//// behind the main branch: the repository is not updated
//_, err = commitFile(remoteRepository, remoteRepositoryDir, "testing", "file-5")
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)
//}

// func TestRepositoryUpdateHardResetMain(t *testing.T) {
// remoteRepositoryDir := t.TempDir()
// cominRepositoryDir := t.TempDir()
// remoteRepository, err := initRemoteRepostiory(remoteRepositoryDir, true)
// assert.Nil(t, err)

//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "origin",
//URL:  remoteRepositoryDir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, "")

//// The remote repository is initially checkouted
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, HeadCommitId(r.Repository), r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// Two commits are added to get a previous commit hash in
//// order to reset it.
//previousHash, err := commitFile(remoteRepository, remoteRepositoryDir, "main", "file-4")
//newCommitId, err := commitFile(remoteRepository, remoteRepositoryDir, "main", "file-5")

//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// The last commit of the main branch is removed.
//// FIXME: ideally we should provide a message saying no valid main branch has been found
//ref := plumbing.NewHashReference("refs/heads/main", plumbing.NewHash(previousHash))
//err = remoteRepository.Storer.SetReference(ref)
//if err != nil {
//return
//}
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, newCommitId, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)
//assert.Contains(t, r.RepositoryStatus.Remotes[0].Main.ErrorMsg, "This branch has been hard reset")
//}

// func TestRepositoryUpdateTesting(t *testing.T) {
// remoteRepositoryDir := t.TempDir()
// cominRepositoryDir := t.TempDir()
// remoteRepository, err := initRemoteRepostiory(remoteRepositoryDir, true)
// assert.Nil(t, err)

//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "origin",
//URL:  remoteRepositoryDir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, _ := New(gitConfig, "")

//// The remote repository is initially checkouted on main
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, HeadCommitId(r.Repository), r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// A new commit is pushed to the testing branch remote repository: the local
//// repository is updated
//commitId4, err := commitFile(remoteRepository, remoteRepositoryDir, "testing", "file-4")
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, commitId4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// A new commit is pushed to the testing branch remote repository: the local
//// repository is updated
//commitId5, err := commitFile(remoteRepository, remoteRepositoryDir, "testing", "file-5")
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, commitId5, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)

//// The main branch is rebased on top of testing: we switch
//// back the the main branch
//testingHeadRef, err := remoteRepository.Reference(
//plumbing.ReferenceName("refs/heads/testing"),
//true)
//ref := plumbing.NewHashReference("refs/heads/main", testingHeadRef.Hash())
//err = remoteRepository.Storer.SetReference(ref)
//if err != nil {
//return
//}
//r.Fetch([]string{"origin"})
//_ = r.Update()
//assert.Equal(t, commitId5, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "origin", r.RepositoryStatus.SelectedRemoteName)
//}

//func TestTestingHardReset(t *testing.T) {
//var err error
//r1Dir := t.TempDir()
//cominRepositoryDir := t.TempDir()
//r1, err := initRemoteRepostiory(r1Dir, true)
//cMain := HeadCommitId(r1)
//gitConfig := types.GitConfig{
//Path: cominRepositoryDir,
//Remotes: []types.Remote{
//{
//Name: "r1",
//URL:  r1Dir,
//Branches: types.Branches{
//Main: types.Branch{
//Name: "main",
//},
//Testing: types.Branch{
//Name: "testing",
//},
//},
//Timeout: 30,
//},
//},
//}
//r, err := New(gitConfig, "")
//assert.Nil(t, err)
//// r1/main: c1 - c2 - *c3
//// r1/testing: c1 - c2 - c3
//r.Fetch([]string{"r1"})
//err = r.Update()
//assert.Nil(t, err)
//assert.Equal(t, cMain, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - c3
//// r1/testing: c1 - c2 - c3 - *c4
//c4, err := commitFile(r1, r1Dir, "testing", "file-4")
//r.Fetch([]string{"r1"})
//err = r.Update()
//assert.Nil(t, err)
//assert.Equal(t, c4, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "testing", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)

//// r1/main: c1 - c2 - *c3
//// r1/testing: c1 - c2 - c3
//ref := plumbing.NewHashReference("refs/heads/testing", plumbing.NewHash(cMain))
//r1.Storer.SetReference(ref)
//r.Fetch([]string{"r1"})
//err = r.Update()
//assert.Nil(t, err)
//assert.Equal(t, cMain, r.RepositoryStatus.SelectedCommitId)
//assert.Equal(t, "main", r.RepositoryStatus.SelectedBranchName)
//assert.Equal(t, "r1", r.RepositoryStatus.SelectedRemoteName)
//}
