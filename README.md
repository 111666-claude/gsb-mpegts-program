# mpegts-program

从 MPEG-TS 的 PAT/PMT 中恢复游戏直播的音视频节目结构，只用 Go 标准库。

## 口径

- 识别 188 字节包、payload 起点、pointer field 与 section 长度。
- PAT 决定节目到 PMT 的映射，PMT 决定 PCR、视频、音频和未知流的 PID。
- 连续性和分段读取不能把下一节误当作当前节，未知流保留但不能冒充音视频。
- 返回 `scanned`，解析过程只随包数增长。

## 不变量

- 输出的 PMT PID 来自 PAT，流 PID 来自对应 PMT。
- 节区间不能越过 section 声明长度。
- 输入含半包时返回错误，不生成半成品节目。

## 输出契约

CLI 输出 JSON：包含 `program_number`、`pmt_pid`、`pcr_pid`、`streams`（`pid` 与 `kind`）和 `scanned`。
