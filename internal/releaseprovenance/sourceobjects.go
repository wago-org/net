package releaseprovenance

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SourceObjectSet selects exact Git commits whose commit objects and complete
// source-tree closures must be exported without depending on a remote ref.
type SourceObjectSet struct {
	Name      string
	Directory string
	Revisions []string
}

// ExportSourceObjects writes one deterministic non-thin Git pack and canonical
// object inventory per repository. Histories outside the selected commits are
// deliberately omitted; each selected commit's complete tree/blob closure is
// included, and selected merge parents can be supplied explicitly.
func ExportSourceObjects(outputDir string, sets []SourceObjectSet) error {
	if outputDir == "" {
		return fmt.Errorf("release provenance: source-object output directory is empty")
	}
	if err := os.RemoveAll(outputDir); err != nil {
		return err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	seen := map[string]struct{}{}
	for _, set := range sets {
		if set.Name == "" || filepath.Base(set.Name) != set.Name || strings.ContainsAny(set.Name, `/\\`) {
			return fmt.Errorf("release provenance: invalid source-object set name %q", set.Name)
		}
		if _, duplicate := seen[set.Name]; duplicate {
			return fmt.Errorf("release provenance: duplicate source-object set %q", set.Name)
		}
		seen[set.Name] = struct{}{}
		if len(set.Revisions) == 0 {
			return fmt.Errorf("release provenance: source-object set %q has no revisions", set.Name)
		}
		objects, err := sourceObjectIDs(set.Directory, set.Revisions)
		if err != nil {
			return fmt.Errorf("release provenance: collect %s source objects: %w", set.Name, err)
		}
		input := []byte(strings.Join(objects, "\n") + "\n")
		inventory, err := gitInput(set.Directory, input, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
		if err != nil {
			return fmt.Errorf("release provenance: inventory %s source objects: %w", set.Name, err)
		}
		if err := os.WriteFile(filepath.Join(outputDir, set.Name+".objects"), inventory, 0o644); err != nil {
			return err
		}
		packPath := filepath.Join(outputDir, set.Name+".pack")
		pack, err := os.OpenFile(packPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		command := exec.Command("git", "-C", set.Directory,
			"-c", "pack.threads=1", "pack-objects", "--stdout", "--window=0", "--compression=9", "--no-reuse-object", "--no-reuse-delta")
		command.Stdin = bytes.NewReader(input)
		command.Stdout = pack
		stderr := new(bytes.Buffer)
		command.Stderr = stderr
		runErr := command.Run()
		closeErr := pack.Close()
		if runErr != nil {
			return fmt.Errorf("release provenance: pack %s source objects: %w: %s", set.Name, runErr, strings.TrimSpace(stderr.String()))
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func verifySourceObjects(root string, manifest *Manifest) error {
	sets := []struct {
		name      string
		revisions []string
		tree      string
	}{
		{name: "net", revisions: []string{manifest.Subject.Revision}, tree: manifest.Subject.Tree},
		{name: "wago", revisions: append([]string{manifest.Inputs[0].Revision}, manifest.Inputs[0].Parents...), tree: manifest.Inputs[0].Tree},
		{name: "lneto", revisions: []string{manifest.Inputs[1].Revision}, tree: manifest.Inputs[1].Tree},
		{name: "wasi", revisions: []string{manifest.Inputs[2].Revision}, tree: manifest.Inputs[2].Tree},
	}
	for _, set := range sets {
		if err := verifySourceObjectSet(root, set.name, set.revisions, set.tree); err != nil {
			return err
		}
	}
	return nil
}

func verifySourceObjectSet(root, name string, revisions []string, expectedTree string) error {
	packPath := filepath.Join(root, "source-objects", name+".pack")
	inventoryPath := filepath.Join(root, "source-objects", name+".objects")
	inventory, err := os.ReadFile(inventoryPath)
	if err != nil {
		return fmt.Errorf("release provenance: read %s source-object inventory: %w", name, err)
	}
	inventoryIDs, err := parseSourceObjectInventory(inventory)
	if err != nil {
		return fmt.Errorf("release provenance: %s source-object inventory: %w", name, err)
	}
	repository, err := os.MkdirTemp("", "wago-net-source-objects-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(repository)
	if data, err := exec.Command("git", "init", "--bare", "--quiet", repository).CombinedOutput(); err != nil {
		return fmt.Errorf("release provenance: initialize %s source-object verifier: %w: %s", name, err, strings.TrimSpace(string(data)))
	}
	pack, err := os.Open(packPath)
	if err != nil {
		return fmt.Errorf("release provenance: open %s source-object pack: %w", name, err)
	}
	index := exec.Command("git", "-C", repository, "index-pack", "--stdin")
	index.Stdin = pack
	indexOutput, indexErr := index.CombinedOutput()
	closeErr := pack.Close()
	if indexErr != nil {
		return fmt.Errorf("release provenance: index %s source-object pack: %w: %s", name, indexErr, strings.TrimSpace(string(indexOutput)))
	}
	if closeErr != nil {
		return closeErr
	}
	fields := strings.Fields(string(indexOutput))
	if len(fields) != 2 || fields[0] != "pack" || !validObjectID(fields[1]) {
		return fmt.Errorf("release provenance: invalid %s source-object pack index result %q", name, strings.TrimSpace(string(indexOutput)))
	}
	packIDs, err := packedObjectIDs(filepath.Join(repository, "objects", "pack", "pack-"+fields[1]+".idx"))
	if err != nil {
		return fmt.Errorf("release provenance: enumerate %s source-object pack: %w", name, err)
	}
	if !equalStrings(packIDs, inventoryIDs) {
		return fmt.Errorf("release provenance: %s source-object pack does not match its canonical inventory", name)
	}
	expectedIDs, err := sourceObjectIDs(repository, revisions)
	if err != nil {
		return fmt.Errorf("release provenance: inspect %s source-object closure: %w", name, err)
	}
	if !equalStrings(expectedIDs, inventoryIDs) {
		return fmt.Errorf("release provenance: %s source-object pack is not the exact selected commit/tree closure", name)
	}
	canonical, err := gitInput(repository, []byte(strings.Join(inventoryIDs, "\n")+"\n"), "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)")
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, inventory) {
		return fmt.Errorf("release provenance: %s source-object inventory metadata is not canonical", name)
	}
	tree, err := gitText(repository, "rev-parse", revisions[0]+"^{tree}")
	if err != nil || tree != expectedTree {
		return fmt.Errorf("release provenance: %s source-object tree %q does not match manifest tree %q", name, tree, expectedTree)
	}
	if name == "wago" {
		commit, err := gitBytes(repository, "cat-file", "-p", revisions[0])
		if err != nil {
			return err
		}
		var parents []string
		for _, line := range strings.Split(string(commit), "\n") {
			if strings.HasPrefix(line, "parent ") {
				parents = append(parents, strings.TrimPrefix(line, "parent "))
			}
		}
		if !equalStringsOrdered(parents, revisions[1:]) {
			return fmt.Errorf("release provenance: Wago source-object pack has wrong ordered merge parents")
		}
	}
	return nil
}

func parseSourceObjectInventory(data []byte) ([]string, error) {
	if len(data) == 0 || data[len(data)-1] != '\n' {
		return nil, fmt.Errorf("inventory is empty or lacks final newline")
	}
	var ids []string
	previous := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 3 || !validObjectID(fields[0]) || fields[0] <= previous {
			return nil, fmt.Errorf("invalid or unsorted inventory line %q", scanner.Text())
		}
		if fields[1] != "commit" && fields[1] != "tree" && fields[1] != "blob" {
			return nil, fmt.Errorf("unsupported object type %q", fields[1])
		}
		if size, err := strconv.ParseInt(fields[2], 10, 64); err != nil || size < 0 {
			return nil, fmt.Errorf("invalid object size %q", fields[2])
		}
		ids = append(ids, fields[0])
		previous = fields[0]
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}

func packedObjectIDs(indexPath string) ([]string, error) {
	data, err := exec.Command("git", "verify-pack", "-v", indexPath).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git verify-pack: %w: %s", err, strings.TrimSpace(string(data)))
	}
	set := map[string]struct{}{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) > 0 && validObjectID(fields[0]) {
			set[fields[0]] = struct{}{}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func equalStringsOrdered(left, right []string) bool { return equalStrings(left, right) }

func sourceObjectIDs(directory string, revisions []string) ([]string, error) {
	set := map[string]struct{}{}
	for _, revision := range revisions {
		commit, err := gitText(directory, "rev-parse", revision+"^{commit}")
		if err != nil {
			return nil, err
		}
		tree, err := gitText(directory, "rev-parse", revision+"^{tree}")
		if err != nil {
			return nil, err
		}
		set[commit], set[tree] = struct{}{}, struct{}{}
		listing, err := gitBytes(directory, "ls-tree", "-r", "-t", "--full-tree", revision)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(bytes.NewReader(listing))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 || (fields[1] != "tree" && fields[1] != "blob") {
				continue
			}
			set[fields[2]] = struct{}{}
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	objects := make([]string, 0, len(set))
	for object := range set {
		objects = append(objects, object)
	}
	sort.Strings(objects)
	return objects, nil
}

func gitText(directory string, args ...string) (string, error) {
	data, err := gitBytes(directory, args...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func gitBytes(directory string, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	data, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	return data, nil
}

func gitInput(directory string, input []byte, args ...string) ([]byte, error) {
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	command.Stdin = bytes.NewReader(input)
	data, err := command.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(data)))
	}
	return data, nil
}
