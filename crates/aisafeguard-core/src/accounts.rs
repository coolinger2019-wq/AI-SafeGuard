//! 本机账号名快照（0.5.10 H200）：为蜜罐凭证喷洒比对提供「本机有哪些用户名」。
//!
//! 设计决定（THREAT_MODEL「凭证库」条目同步）：只取用户名集合，绝不读取、
//! 存储或传输任何真实口令数据——喷洒判定只需要「攻击者试的用户名与本机账号
//! 同名」，不需要口令是否相同。枚举走 sysinfo 的安全封装（Windows 内部
//! NetUserEnum、Linux 读 /etc/passwd），本 crate forbid(unsafe_code) 不破例。

/// 本机「人类用户」用户名集合（小写归一，Windows 用户名不区分大小写）。
/// 枚举失败返回 Err（调用方留 engine 事件，喷洒比对在快照就绪前跳过）。
pub fn local_usernames() -> std::io::Result<Vec<String>> {
    let users = sysinfo::Users::new_with_refreshed_list();
    let mut names: Vec<String> = users
        .list()
        .iter()
        .filter(|u| is_human_account(u))
        .map(|u| u.name().to_lowercase())
        .collect();
    names.sort();
    names.dedup();
    Ok(names)
}

/// 是否「人类用户」账号：
/// - Unix：uid 0（root，喷洒最常撞的目标）或 uid ≥ 1000（常规登录用户）；
///   系统服务账号（daemon/nobody 等）排除——它们没有口令登录面。
/// - Windows：排除系统内置非人类账号（Guest/DefaultAccount/WDAGUtilityAccount）。
#[cfg(unix)]
fn is_human_account(user: &sysinfo::User) -> bool {
    // sysinfo 0.37 起 Uid 字段私有（宏生成，平台异构）：经 Display 解析回 u32 比较。
    // root=0 或常规登录用户 ≥1000；解析失败按人类账号处理（宁少排除不误伤）
    let uid = user.id().to_string().parse::<u32>().unwrap_or(u32::MAX);
    uid == 0 || uid >= 1000
}

#[cfg(not(unix))]
fn is_human_account(user: &sysinfo::User) -> bool {
    let name = user.name().to_lowercase();
    !matches!(
        name.as_str(),
        "guest" | "defaultaccount" | "wdagutilityaccount"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_never_panics_and_names_lowercase() {
        // 只断言不炸 + 输出形态：CI 容器可能没有任何人类用户账号
        let names = local_usernames().expect("枚举本身不应失败");
        for n in &names {
            assert!(!n.is_empty());
            assert_eq!(*n, n.to_lowercase(), "用户名应小写归一: {n}");
            assert!(!n.contains(':'), "不应携带 /etc/passwd 分隔符: {n}");
        }
    }
}
