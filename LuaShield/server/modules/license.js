const { toSeconds, nowSeconds } = require("./time");

/**
 * Returns null when the license may run, otherwise the reason it can't:
 * disabled | project | hwid | expired | quota
 */
function evaluate(User, { ProjectID, HWID, CheckQuota = false }) {
    if (!User || !User.Whitelisted) return "disabled";
    if (User.ProjectID !== ProjectID) return "project";
    if (User.HWID && User.HWID !== HWID) return "hwid";
    const ExpireAt = toSeconds(User.ExpireAt);
    if (ExpireAt && nowSeconds() >= ExpireAt) return "expired";
    if (CheckQuota && User.MaxExecutions > 0 && User.Executions >= User.MaxExecutions) return "quota";
    return null;
}

module.exports = { evaluate };
