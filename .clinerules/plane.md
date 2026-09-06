# Plane連携ルール

## 作業フロー

- 作業開始時に対象Issueを確認する
- 作業開始したらIssueをIn Progressにする
- 実装上の重要な進展をIssueコメントに記録する
- テスト結果をIssueコメントに記録する
- 作業完了時に実装内容とテスト結果をコメントする
- 完了条件を満たしたらIssueをDoneにする
- Issue番号が指定されていない場合、PlaneのIssueを変更しない
- 作業開始時にStart dateを入れる
- 作業完了時にEnd dateを入れる
- チケット起票時にCycleは設定されている最新のCycleを入れる

## 重要

- PlaneのIssueを変更する前に、必ず対象Issueを確認する
- Issue番号が明示されていない作業では、Plane上のIssueを作成・変更しない
- コード変更だけでなく、テスト結果もPlaneに記録する
- 作業途中で重大な問題が発生した場合は、Plane Issueにコメントする

---

## タスク取得手順

### 注意: PQL制約

このワークスペースのPlaneエディションでは **PQL (Plane Query Language) がサポートされていません**。
`pql` パラメータを渡すとエラーになるため、 **全件取得後にクライアント側でフィルタリング** する運用とする。

### プロジェクトID一覧

| プロジェクト名 | 識別子 | プロジェクトID |
|---------------|--------|---------------|
| Linux Remote Management MCP | LINUX | `6c63ace2-9ce9-4130-a833-3c7a10384c27` |
| LocalLLM IF | LLM | `e08de800-95aa-4b5a-96e0-3a44578a10b0` |
| keiba_db | KEIBA | `8d94b194-3117-4e1b-9eae-5c0e232f2c69` |
| Loto7 ML Prediction System | LOTO7 | `eb6fbf66-85be-481a-9a61-e67654778908` |
| SAMI | SAMI | `8d366091-2bca-4ac8-bfac-a5bb7f297e79` |

### 残タスク取得の基本フロー

1. **プロジェクトを特定** → 上記テーブルからプロジェクトIDを取得
2. **全ワークアイテム取得** → `workitem list` を `project_id` 指定で実行（PQL不可）
3. **クライアント側フィルタリング** → 以下を除外:
   - `completed_at` が null 以外（完了済み）
   - `state` が完了/キャンセル相当のステータス

### ステータスUUID参照

| ステータス | UUID |
|-----------|------|
| Completed | `6ba655ab-b832-4509-aca6-c5c09e2bd136` |
| Cancelled | `f7a22c55-ccc3-4a48-a273-69c4ada80819` |

### フィルタリング例（疑似コード）

```python
# 残タスク抽出ロジック
EXCLUDED_STATES = {
    "6ba655ab-b832-4509-aca6-c5c09e2bd136",  # completed
    "f7a22c55-ccc3-4a48-a273-69c4ada80819",  # cancelled
}

remaining_tasks = [
    item for item in all_items
    if item["state"] not in EXCLUDED_STATES
    and item["completed_at"] is None
    and item["archived_at"] is None
    and item["is_draft"] is False
]
```

### 優先度ソート

取得後は `priority` フィールドでソートすると作業順序を決めやすい：
- `urgent` → `high` → `medium` → `low` → `none`

---

## 新規チケット作成時のチェックリスト

- [ ] タイトルにタスク番号プレフィックスを付与（例: `[P0-1]`, `[P2-12]`）
- [ ] 親Issue（エピック）を `parent` に指定
- [ ] 優先度を設定
- [ ] 最新のCycleを設定
- [ ] 担当者が決まっていれば `assignees` に設定