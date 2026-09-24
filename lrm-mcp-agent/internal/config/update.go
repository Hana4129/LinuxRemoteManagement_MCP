package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// ReadSecret は secret をファイル、または標準入力 ("-") から読み取る。
//
// 末尾の改行のみを取り除く (secret 本体に含まれる空白はそのまま扱う)。
// 空の secret は受け付けない。
func ReadSecret(source string) (string, error) {
	var (
		data []byte
		err  error
	)
	if source == "-" {
		data, err = io.ReadAll(os.Stdin)
	} else {
		data, err = os.ReadFile(source)
	}
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	secret := strings.TrimRight(string(data), "\r\n")
	if strings.TrimSpace(secret) == "" {
		return "", fmt.Errorf("secret is empty (%s)", source)
	}
	return secret, nil
}

// HashSecret は secret の SHA-256 hex 表現を返す。
//
// Agent 側の config.yml (`agent.admin_token_hash`) と `tokens[].hash`、
// および Console 側が照合に使う形式と同一。
func HashSecret(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

// SetAdminTokenHash は config.yml の agent.admin_token_hash を hash で更新する。
//
// 既存のコメントや未知のキーを保持するため、yaml.Node を直接編集して書き戻す。
//   - 既存値が hash と同一なら何も書かずに (false, nil) を返す (冪等)
//   - 既存値が異なり replace が false なら上書きせずエラー (黙って置換しない)
//   - replace が true のときだけ新しい hash で置き換える
//
// 第2戻り値は実際に書き換えたかどうかを表す。
func SetAdminTokenHash(path, hash string, replace bool) (bool, error) {
	if strings.TrimSpace(hash) == "" {
		return false, fmt.Errorf("hash is empty")
	}
	doc, mode, err := loadDocument(path)
	if err != nil {
		return false, err
	}
	root, err := rootMapping(doc)
	if err != nil {
		return false, err
	}
	agentMap, err := childMapping(root, "agent")
	if err != nil {
		return false, err
	}
	if cur := mapValue(agentMap, "admin_token_hash"); cur != nil &&
		cur.Kind == yaml.ScalarNode && strings.TrimSpace(cur.Value) != "" {
		if cur.Value == hash {
			return false, nil
		}
		if !replace {
			return false, fmt.Errorf(
				"agent.admin_token_hash is already set to a different value; " +
					"pass -replace-admin-token to overwrite it")
		}
	}
	setMapValue(agentMap, "admin_token_hash", hash)
	if err := saveDocument(path, doc, mode); err != nil {
		return false, err
	}
	return true, nil
}

// AppendTokenEntry は config.yml の agent.tokens へ token entry を追記する。
//
// 既存のコメントや未知のキーは保持される。token id が重複する場合は
// 書き込まずにエラーを返す (既存 credential を壊さないため)。
// 更新前の内容は <path>.bak (0600) へ退避する。
func AppendTokenEntry(path string, entry TokenEntry) error {
	if strings.TrimSpace(entry.ID) == "" {
		return fmt.Errorf("token id is empty")
	}
	doc, mode, err := loadDocument(path)
	if err != nil {
		return err
	}
	root, err := rootMapping(doc)
	if err != nil {
		return err
	}
	agentMap, err := childMapping(root, "agent")
	if err != nil {
		return err
	}
	tokens, err := childSequence(agentMap, "tokens")
	if err != nil {
		return err
	}
	for _, item := range tokens.Content {
		if item.Kind != yaml.MappingNode {
			continue
		}
		if v := mapValue(item, "id"); v != nil && v.Value == entry.ID {
			return fmt.Errorf("token id %q already exists in %s", entry.ID, path)
		}
	}
	tokens.Content = append(tokens.Content, tokenEntryNode(entry))
	return saveDocument(path, doc, mode)
}

func tokenEntryNode(e TokenEntry) *yaml.Node {
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendScalar(m, "id", e.ID)
	appendScalar(m, "name", e.Name)
	appendScalar(m, "hash", e.Hash)
	appendScalar(m, "scope", e.Scope)
	return m
}

// loadDocument は YAML を Node として読み込み、元ファイルの権限も返す。
func loadDocument(path string) (*yaml.Node, os.FileMode, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("config read: %w", err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("config parse: %w", err)
	}
	mode := os.FileMode(0o600)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	return &doc, mode, nil
}

// saveDocument は更新後の YAML を書き戻す。書き込み前に元の内容を .bak へ退避する。
//
// インデントは既存の config.yml に合わせて2スペースで出力する。
func saveDocument(path string, doc *yaml.Node, mode os.FileMode) error {
	if data, err := os.ReadFile(path); err == nil {
		if err := os.WriteFile(path+".bak", data, 0o600); err != nil {
			return fmt.Errorf("backup write: %w", err)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return fmt.Errorf("config marshal: %w", err)
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("config marshal: %w", err)
	}
	if mode == 0 {
		mode = 0o600
	}
	if err := os.WriteFile(path, buf.Bytes(), mode); err != nil {
		return fmt.Errorf("config write: %w", err)
	}
	return nil
}

// rootMapping はドキュメントのルートマッピングを返す。空ファイルなら新規作成する。
func rootMapping(doc *yaml.Node) (*yaml.Node, error) {
	if doc.Kind == 0 {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Kind = yaml.DocumentNode
		doc.Content = []*yaml.Node{m}
		return m, nil
	}
	if doc.Kind == yaml.MappingNode {
		return doc, nil
	}
	if doc.Kind != yaml.DocumentNode {
		return nil, fmt.Errorf("config root is not a mapping")
	}
	if len(doc.Content) == 0 {
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Content = []*yaml.Node{m}
		return m, nil
	}
	node := doc.Content[0]
	if node.Kind == yaml.MappingNode {
		return node, nil
	}
	if node.Kind == yaml.ScalarNode && (node.Tag == "!!null" || node.Value == "") {
		// 空ファイルやコメントのみのファイルは空マッピングとして扱う。
		m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		doc.Content[0] = m
		return m, nil
	}
	return nil, fmt.Errorf("config root is not a mapping")
}

// mapValue はマッピング内の key に対応する値ノードを返す (無ければ nil)。
func mapValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// childMapping は key のマッピングを返す。無ければ作成して追記する。
func childMapping(parent *yaml.Node, key string) (*yaml.Node, error) {
	if v := mapValue(parent, key); v != nil {
		if v.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s is not a mapping in config.yml", key)
		}
		return v, nil
	}
	m := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendKeyValue(parent, key, m)
	return m, nil
}

// childSequence は key のシーケンスを返す。無ければ作成して追記する。
func childSequence(parent *yaml.Node, key string) (*yaml.Node, error) {
	if v := mapValue(parent, key); v != nil {
		if v.Kind == yaml.SequenceNode {
			return v, nil
		}
		if v.Kind == yaml.ScalarNode && (v.Tag == "!!null" || v.Value == "") {
			// `tokens:` のみ書かれている場合は空シーケンスへ置き換える。
			v.Kind = yaml.SequenceNode
			v.Tag = "!!seq"
			v.Value = ""
			v.Style = 0
			v.Content = nil
			return v, nil
		}
		return nil, fmt.Errorf("%s is not a sequence in config.yml", key)
	}
	seq := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	appendKeyValue(parent, key, seq)
	return seq, nil
}

// setMapValue はマッピング内の key を value へ更新する。無ければ追記する。
func setMapValue(m *yaml.Node, key, value string) {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value != key {
			continue
		}
		node := m.Content[i+1]
		if node.Kind == yaml.ScalarNode {
			node.Value = value
			node.Tag = "!!str"
			node.Style = 0
			return
		}
		m.Content[i+1] = &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value}
		return
	}
	appendScalar(m, key, value)
}

func appendScalar(m *yaml.Node, key, value string) {
	appendKeyValue(m, key, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value})
}

func appendKeyValue(m *yaml.Node, key string, value *yaml.Node) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		value,
	)
}
