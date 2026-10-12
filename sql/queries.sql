-- The four patterns that answer ~90% of compliance analytics questions.
-- (Works in SQLite; the window functions also work in Postgres / Snowflake / BigQuery.)

-- 1) Latest status per control, per account
SELECT control_id, account, status
FROM (
  SELECT control_id, account, status,
         ROW_NUMBER() OVER (PARTITION BY control_id, account ORDER BY tested_at DESC) AS rn
  FROM control_results
)
WHERE rn = 1;

-- 2) Findings that are open but have NO ticket (anti-join)
SELECT f.id, f.severity
FROM findings f
LEFT JOIN tickets t ON t.finding_id = f.id
WHERE f.status = 'open' AND t.id IS NULL;

-- 3) Assets with no owner (anti-join to the team registry)
SELECT a.id, a.name
FROM assets a
LEFT JOIN owners o ON o.team = a.owner_team
WHERE o.team IS NULL;

-- 4) Controls that flipped from PASS to FAIL (drift, in SQL)
SELECT control_id, account, tested_at
FROM (
  SELECT control_id, account, status, tested_at,
         LAG(status) OVER (PARTITION BY control_id, account ORDER BY tested_at) AS prev
  FROM control_results
)
WHERE prev = 'PASS' AND status = 'FAIL';

-- Bonus: pass rate per framework
SELECT c.framework,
       ROUND(SUM(CASE WHEN r.status = 'PASS' THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 1) AS pass_pct
FROM control_results r
JOIN controls c ON c.id = r.control_id
GROUP BY c.framework;

-- Bonus: mean time to resolve (days) per team
SELECT assignee_team,
       ROUND(AVG(julianday(closed_at) - julianday(created_at)), 1) AS avg_days
FROM tickets
WHERE status = 'closed'
GROUP BY assignee_team;
