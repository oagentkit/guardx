package logredact

// 「保定位线索的不可逆掩码」——与全量打码（****）**不同档**，不是替代关系。
//
// 为什么需要这一档：全量打码让处置后的文本**失去定位能力**——用户回头问
// 「我那条凭据呢」时，没人能指出是哪一条。而掩码又必须**不可复原**
// （凭据一旦落库就是不可逆的），所以「保留定位线索」与「不可复原」这对要求
// 只能靠**保留位数封顶**来同时满足：保留首尾各若干字符，且**保留位数不随
// 原值长度变化**。
//
// 为什么不随原值长度变化：保留位数若随长度线性增长，长凭据会泄掉一大截，
// 短凭据又什么都留不下——那就不是「封顶」，是「按比例泄露」。

// DefaultHintKeep 保定位线索掩码默认保留位数（首尾各）。
const DefaultHintKeep = 4

// HintMinLenRatio 被掩值长度不足 keep*该倍数 时**全量打码**。
//
// 阈值的作用是「留了也别等于没留」：9 字符的 secret 留首尾 4 个 = 8 个字符，
// 换个字符就复原了——那不是定位线索，是泄露。保留的字符数必须远小于被藏起的
// 字符数，掩码才真的不可逆。
const HintMinLenRatio = 4

// fullMask 全量打码的固定字面量（长度固定 → 不泄露原值长度）。
const fullMask = "****"

// MaskHint 保留首尾各 DefaultHintKeep 字符的不可逆掩码。
//
// 输出形如 "sk-a****mnop"：长度**固定**（与原值长度无关），
// 保留位**封顶**（与原值长度无关），中间恒为固定长度的星号。
//
// 长度不足时返回全量打码 "****"（理由见 HintMinLenRatio）。
// 空串返回空串。
func MaskHint(s string) string {
	return MaskHintWith(s, DefaultHintKeep)
}

// MaskHintWith 保留首尾各 keep 字符的不可逆掩码。
//
// keep<=0 取 DefaultHintKeep。被掩值长度不足 keep*HintMinLenRatio 时全量打码。
// 空串返回空串。
func MaskHintWith(s string, keep int) string {
	if s == "" {
		return ""
	}
	if keep <= 0 {
		keep = DefaultHintKeep
	}
	runes := []rune(s)
	if len(runes) < keep*HintMinLenRatio {
		return fullMask
	}
	return string(runes[:keep]) + fullMask + string(runes[len(runes)-keep:])
}
