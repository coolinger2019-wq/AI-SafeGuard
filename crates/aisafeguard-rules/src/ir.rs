//! 规则 IR（v1 子集，字段与 docs/RULESET_SUBSET.md 冻结表一一对应）。
//!
//! 设计：纯数据 + 纯函数匹配，无 IO、无时钟——threshold 的计时由调用方
//! 传入 ts（可测试、可热更），本模块不做任何副作用。

use std::net::IpAddr;

/// 协议（v1 子集仅 tcp/udp）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Proto {
    Tcp,
    Udp,
}

impl Proto {
    pub fn name(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }
}

/// 规则头方向：`->` 单向 / `<>` 双向。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Uni,
    Bi,
}

/// 单个地址项（可带 `!` 否定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddrItem {
    pub neg: bool,
    pub addr: Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Addr {
    Ip(IpAddr),
    Cidr { base: IpAddr, prefix: u8 },
}

/// 地址规格：any / $HOME_NET / $EXTERNAL_NET / 显式列表（内可混合变量与 CIDR）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddrSpec {
    Any,
    HomeNet,
    ExternalNet,
    List(Vec<AddrItem>),
}

/// 端口范围（含端点，可带 `!` 否定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
    pub neg: bool,
}

/// 端口规格。ranges 为空 = `any`（匹配任意端口）。
/// 匹配语义：命中否定项 → 不匹配；无肯定项（纯否定/any）→ 不被否定即匹配；
/// 否则需命中任一肯定项。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortSpec {
    pub ranges: Vec<PortRange>,
}

impl PortSpec {
    pub fn any() -> Self {
        Self { ranges: Vec::new() }
    }

    pub fn matches(&self, p: u16) -> bool {
        if self.ranges.is_empty() {
            return true;
        }
        if self.ranges.iter().any(|r| r.neg && r.lo <= p && p <= r.hi) {
            return false;
        }
        match self.ranges.iter().any(|r| !r.neg && r.lo <= p && p <= r.hi) {
            true => true,
            false => self.ranges.iter().all(|r| r.neg),
        }
    }
}

/// flow 标志（子集：established / to_server / from_server）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Flow {
    pub established: bool,
    pub to_server: bool,
    pub from_server: bool,
}

/// F780 粘性缓冲区：content/pcre 的匹配目标区域。Raw = 原始窗口（未指定时
/// 缺省——既有规则行为一字不变）；其余 = HTTP 请求的语义段（非 HTTP 窗口
/// 上带缓冲区的规则不可达 = false）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentBuf {
    #[default]
    Raw,
    Method,
    Uri,
    Header,
    UserAgent,
    ClientBody,
}

/// 子集支持的粘性缓冲区关键字（v1 → v2：五格）；其他 http_*/tls.*/file_data 仍拒绝。
pub fn buffer_for_kw(kw: &str) -> Option<ContentBuf> {
    match kw {
        "http_method" => Some(ContentBuf::Method),
        "http_uri" => Some(ContentBuf::Uri),
        "http_header" => Some(ContentBuf::Header),
        "http_user_agent" => Some(ContentBuf::UserAgent),
        "http_client_body" => Some(ContentBuf::ClientBody),
        _ => None,
    }
}

/// 单条 content 匹配（顺序 AND；修饰符语义见 matcher）。
#[derive(Debug, Clone)]
pub struct ContentMatch {
    pub bytes: Vec<u8>,
    pub nocase: bool,
    pub offset: Option<u32>,
    pub depth: Option<u32>,
    pub distance: Option<u32>,
    pub within: Option<u32>,
    pub buf: ContentBuf,
}

/// pcre 匹配（已编译 rust regex；relative = `R` 标志，锚定上一匹配之后）。
#[derive(Debug, Clone)]
pub struct PcreMatch {
    pub re: regex::Regex,
    pub relative: bool,
    /// F780：pcre 的目标缓冲区（粘性/修饰符同 content 规则）
    pub buf: ContentBuf,
}

/// threshold 类型（子集：limit / both）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdKind {
    /// 窗口内首条触发，其余抑制
    Limit,
    /// 窗口内第 count 条触发（且受窗口冷却）
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Threshold {
    pub kind: ThresholdKind,
    pub by_src: bool,
    pub count: u32,
    pub seconds: i64,
}

/// 解析后的规则。
#[derive(Debug, Clone)]
pub struct Rule {
    pub proto: Proto,
    pub src: AddrSpec,
    pub src_port: PortSpec,
    pub direction: Direction,
    pub dst: AddrSpec,
    pub dst_port: PortSpec,
    pub flow: Flow,
    pub msg: String,
    pub sid: u32,
    pub rev: u32,
    pub classtype: Option<String>,
    /// metadata 透传标签（不参与匹配）
    pub metadata: Vec<String>,
    pub contents: Vec<ContentMatch>,
    pub pcre: Vec<PcreMatch>,
    pub threshold: Option<Threshold>,
}

impl Rule {
    /// 事件里的规则标识（口径见子集规范「命中产出」）。
    pub fn rule_id(&self) -> String {
        format!("sid:{}", self.sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec_any_and_lists() {
        assert!(PortSpec::any().matches(0));
        assert!(PortSpec::any().matches(65535));

        let spec = || PortSpec {
            ranges: vec![PortRange {
                lo: 1,
                hi: 1024,
                neg: false,
            }],
        };
        assert!(spec().matches(1));
        assert!(spec().matches(1024));
        assert!(!spec().matches(1025));

        // !80：纯否定——除 80 之外都匹配
        let neg = PortSpec {
            ranges: vec![PortRange {
                lo: 80,
                hi: 80,
                neg: true,
            }],
        };
        assert!(!neg.matches(80));
        assert!(neg.matches(81));

        // 肯定 + 否定混合
        let mixed = PortSpec {
            ranges: vec![
                PortRange {
                    lo: 1,
                    hi: 1024,
                    neg: false,
                },
                PortRange {
                    lo: 500,
                    hi: 500,
                    neg: true,
                },
            ],
        };
        assert!(mixed.matches(80));
        assert!(!mixed.matches(500));
        assert!(!mixed.matches(2000));
    }
}
