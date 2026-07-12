package releaseprovenance

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// SourceObjectExportOptions configures release artifact path validation.
// Output is constrained beneath ArtifactRoot unless AllowOutsideArtifactRoot is
// set explicitly.
type SourceObjectExportOptions struct {
	RepositoryRoot           string
	ArtifactRoot             string
	WorkingDirectory         string
	HomeDirectory            string
	AllowOutsideArtifactRoot bool
}

type preparedArtifactDirectory struct {
	outputDir string
}

func prepareSourceObjectOutputDirectory(outputDir string, sets []SourceObjectSet, options SourceObjectExportOptions) (preparedArtifactDirectory, error) {
	if outputDir == "" {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: source-object output directory is empty")
	}
	resolvedOutput, symlinkTargets, err := resolveArtifactPath(outputDir)
	if err != nil {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: resolve source-object output directory: %w", err)
	}
	if resolvedOutput == string(filepath.Separator) {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: refusing filesystem root", resolvedOutput)
	}

	repositoryRoot := options.RepositoryRoot
	if repositoryRoot == "" && len(sets) > 0 {
		repositoryRoot = sets[0].Directory
	}
	if repositoryRoot == "" {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: repository root is required for source-object output validation")
	}
	resolvedRepositoryRoot, _, err := resolveArtifactPath(repositoryRoot)
	if err != nil {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: resolve repository root: %w", err)
	}

	artifactRoot := options.ArtifactRoot
	if artifactRoot == "" {
		artifactRoot = filepath.Join(resolvedRepositoryRoot, ".wago")
	}
	resolvedArtifactRoot, _, err := resolveArtifactPath(artifactRoot)
	if err != nil {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: resolve artifact root: %w", err)
	}
	workingDirectory := options.WorkingDirectory
	if workingDirectory == "" {
		workingDirectory, err = os.Getwd()
		if err != nil {
			return preparedArtifactDirectory{}, err
		}
	}
	resolvedWorkingDirectory, _, err := resolveArtifactPath(workingDirectory)
	if err != nil {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: resolve working directory: %w", err)
	}
	if pathContains(resolvedOutput, resolvedWorkingDirectory) {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: refusing to replace the current working directory or one of its ancestors", resolvedOutput)
	}

	homeDirectory := options.HomeDirectory
	if homeDirectory == "" {
		homeDirectory, err = os.UserHomeDir()
		if err != nil {
			return preparedArtifactDirectory{}, err
		}
	}
	resolvedHomeDirectory, _, err := resolveArtifactPath(homeDirectory)
	if err != nil {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: resolve home directory: %w", err)
	}
	if resolvedOutput == resolvedHomeDirectory {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: refusing the current user's home directory", resolvedOutput)
	}

	unsafeRoots := []string{resolvedRepositoryRoot, resolvedHomeDirectory}
	for _, set := range sets {
		resolvedSourceRoot, _, err := resolveArtifactPath(set.Directory)
		if err != nil {
			return preparedArtifactDirectory{}, fmt.Errorf("release provenance: resolve source repository %q: %w", set.Name, err)
		}
		unsafeRoots = append(unsafeRoots, resolvedSourceRoot)
		if pathContains(resolvedOutput, resolvedSourceRoot) {
			return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: refusing source repository %q or one of its ancestors", resolvedOutput, resolvedSourceRoot)
		}
	}
	for _, target := range symlinkTargets {
		if target == string(filepath.Separator) {
			return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: a path component resolves through the filesystem root", resolvedOutput)
		}
		if target == resolvedWorkingDirectory || pathContains(target, resolvedWorkingDirectory) {
			return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: a path component resolves through the current working directory or one of its ancestors", resolvedOutput)
		}
		for _, unsafeRoot := range unsafeRoots {
			if target == unsafeRoot || pathContains(target, unsafeRoot) {
				return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: a path component resolves through %q", resolvedOutput, unsafeRoot)
			}
		}
	}
	if resolvedOutput == resolvedArtifactRoot {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: output must be beneath %q, not the artifact root itself", resolvedOutput, resolvedArtifactRoot)
	}
	if !options.AllowOutsideArtifactRoot && !pathWithin(resolvedArtifactRoot, resolvedOutput) {
		return preparedArtifactDirectory{}, fmt.Errorf("release provenance: unsafe source-object output directory %q: output must be beneath %q unless an explicit override is set", resolvedOutput, resolvedArtifactRoot)
	}
	return preparedArtifactDirectory{outputDir: resolvedOutput}, nil
}

func replaceDirectoryAtomically(outputDir string, generate func(string) error) error {
	parent := filepath.Dir(outputDir)
	base := filepath.Base(outputDir)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return err
	}
	stageDir, err := os.MkdirTemp(parent, "."+base+".tmp-")
	if err != nil {
		return err
	}
	cleanupStage := true
	defer func() {
		if cleanupStage {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := generate(stageDir); err != nil {
		return err
	}

	info, err := os.Stat(outputDir)
	switch {
	case err == nil && !info.IsDir():
		return fmt.Errorf("release provenance: existing source-object output path %q is not a directory", outputDir)
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return err
	}
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Rename(stageDir, outputDir); err != nil {
			return err
		}
		cleanupStage = false
		return nil
	}

	backupDir := filepath.Join(parent, "."+base+".previous-"+filepath.Base(stageDir))
	if err := os.Rename(outputDir, backupDir); err != nil {
		return err
	}
	if err := os.Rename(stageDir, outputDir); err != nil {
		if restoreErr := os.Rename(backupDir, outputDir); restoreErr != nil {
			return fmt.Errorf("release provenance: replace %q: %w (restore previous output: %v)", outputDir, err, restoreErr)
		}
		return err
	}
	cleanupStage = false
	if err := os.RemoveAll(backupDir); err != nil {
		return fmt.Errorf("release provenance: cleanup previous source-object output %q: %w", backupDir, err)
	}
	return nil
}

func resolveArtifactPath(path string) (string, []string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	absPath = filepath.Clean(absPath)
	current := absPath
	var unresolved []string
	for {
		if _, err := os.Lstat(current); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return "", nil, err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		unresolved = append(unresolved, filepath.Base(current))
		current = parent
	}
	resolvedExisting, symlinkTargets, err := resolveExistingPath(current)
	if err != nil {
		return "", nil, err
	}
	resolved := resolvedExisting
	for i := len(unresolved) - 1; i >= 0; i-- {
		resolved = filepath.Join(resolved, unresolved[i])
	}
	return filepath.Clean(resolved), symlinkTargets, nil
}

func resolveExistingPath(path string) (string, []string, error) {
	path = filepath.Clean(path)
	if path == string(filepath.Separator) {
		return path, nil, nil
	}
	volume := filepath.VolumeName(path)
	root := volume + string(filepath.Separator)
	rest := strings.TrimPrefix(path, root)
	current := root
	var symlinkTargets []string
	if rest == "" {
		return current, symlinkTargets, nil
	}
	for _, component := range strings.Split(rest, string(filepath.Separator)) {
		next := filepath.Join(current, component)
		info, err := os.Lstat(next)
		if err != nil {
			return "", nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			resolvedTarget, err := filepath.EvalSymlinks(next)
			if err != nil {
				return "", nil, err
			}
			resolvedTarget, err = filepath.Abs(resolvedTarget)
			if err != nil {
				return "", nil, err
			}
			resolvedTarget = filepath.Clean(resolvedTarget)
			symlinkTargets = append(symlinkTargets, resolvedTarget)
			current = resolvedTarget
			continue
		}
		current = next
	}
	return filepath.Clean(current), symlinkTargets, nil
}

func pathWithin(parent, child string) bool {
	return parent != child && pathContains(parent, child)
}

func pathContains(parent, child string) bool {
	if parent == child {
		return true
	}
	if parent == string(filepath.Separator) {
		return strings.HasPrefix(child, string(filepath.Separator))
	}
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
