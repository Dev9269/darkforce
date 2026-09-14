import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  AlertTriangle, ArrowLeft, CircleHelp, Eye, FolderOpen, LoaderCircle, Plus, ShieldAlert, Trash2, UserRound,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  addCaseMember, createCase, errorText, getAlerts, getCase, getCases, getText, patchCaseStatus,
  removeCaseMember, runOpsDetect,
  type CaseHeader, type LiveAlert,
} from "@/lib/darkforce";

const STATUSES = ["open", "watch", "closed"];
const MEMBER_TYPES = ["site", "identifier", "actor", "finding", "link", "wallet"];

function OpsPanel() {
  const queryClient = useQueryClient();
  const detect = useMutation({
    mutationFn: runOpsDetect,
    onSuccess: (result) => {
      toast.success(`${result.gone_dark_alerts ?? 0} gone-dark alerts, ${result.successor_alerts ?? 0} successor alerts`);
      void queryClient.invalidateQueries({ queryKey: ["alerts"] });
    },
    onError: (error) => toast.error(`Ops detect failed: ${errorText(error)}`),
  });

  return (
    <section className="console-panel" data-testid="ops-detect-panel">
      <div className="panel-heading">
        <div>
          <div className="section-kicker"><ShieldAlert size={14} /> OPERATIONAL DETECTION <span className="mono">/ GO-DARK &amp; SUCCESSOR SCAN</span></div>
          <div className="panel-subtitle">Mark previously-reachable sites that stopped resolving; flag new sites broadcasting successor propaganda</div>
        </div>
        <Button variant="outline" disabled={detect.isPending} onClick={() => detect.mutate()} data-testid="ops-detect-button">
          {detect.isPending ? <LoaderCircle className="animate-spin" size={14} /> : <Eye size={14} />} Run detect
        </Button>
      </div>
      {detect.data && (
        <div className="stat-detail-table-stack" data-testid="ops-detect-result">
          <div className="panel-subtitle mono">{(detect.data.gone_dark ?? []).length} gone-dark · {(detect.data.candidates ?? []).length} successor candidates</div>
          {(detect.data.gone_dark ?? []).map((row) => (
            <div className="finding-item severity-high" key={row.url}>
              <div className="finding-title">GONE DARK — {getText(row.title, getText(row.url))}</div>
              <div className="finding-detail">
                <div className="finding-source mono">{row.url} · {getText(row.category, "?")} · last scan {getText(row.last_scan, "?")}</div>
              </div>
            </div>
          ))}
          {(detect.data.candidates ?? []).map((row) => (
            <div className="finding-item severity-medium" key={`${row.url}-${row.hint}`}>
              <div className="finding-title">SUCCESSOR CANDIDATE — {getText(row.title, getText(row.url))}</div>
              <div className="finding-detail">
                <div className="finding-source mono">{row.url} · hint / {getText(row.hint, "?")}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function OpsAlerts({ alerts }: { alerts: LiveAlert[] }) {
  const ops = alerts.filter((alert) => ["sites_gone_dark", "successor_suspected"].includes(getText(alert.kind)));
  if (!ops.length) return null;
  return (
    <section className="console-panel" data-testid="ops-alerts-panel">
      <div className="panel-heading">
        <div>
          <div className="section-kicker"><AlertTriangle size={14} /> LIVE OPS ALERTS</div>
          <div className="panel-subtitle">Automated detections raised by the pipeline</div>
        </div>
      </div>
      <div className="finding-stack">
        {ops.map((alert) => (
          <details key={String(alert.id ?? alert.created_at)} className={`finding-item ${getText(alert.kind) === "sites_gone_dark" ? "severity-high" : "severity-medium"}`} open>
            <summary><span className="severity-dot" /><span className="finding-title">{getText(alert.title)}</span></summary>
            <div className="finding-detail">
              <div className="finding-source mono">{getText(alert.url, "")} · {getText(alert.kind, "ops")} · {getText(alert.created_at, "")}</div>
            </div>
          </details>
        ))}
      </div>
    </section>
  );
}

export default function Cases() {
  const queryClient = useQueryClient();
  const [statusFilter, setStatusFilter] = useState("");
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [name, setName] = useState("");
  const [createStatus, setCreateStatus] = useState("open");
  const [owner, setOwner] = useState("analyst");
  const [notes, setNotes] = useState("");
  const [memberType, setMemberType] = useState("site");
  const [memberId, setMemberId] = useState("");
  const [memberLabel, setMemberLabel] = useState("");
  const [memberNote, setMemberNote] = useState("");
  const [memberTag, setMemberTag] = useState("");

  const casesQuery = useQuery({ queryKey: ["cases", statusFilter], queryFn: () => getCases(statusFilter || undefined), retry: false });
  const caseQuery = useQuery({ queryKey: ["case", selectedId], queryFn: () => getCase(selectedId!), enabled: Boolean(selectedId), retry: false });
  const alertsQuery = useQuery({ queryKey: ["alerts-ops"], queryFn: getAlerts, refetchInterval: 30_000, retry: false });

  const createMutation = useMutation({
    mutationFn: () => createCase({ name, status: createStatus, owner, notes }),
    onSuccess: () => {
      toast.success(`Case opened: ${name}`);
      setName(""); setNotes("");
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: (error) => toast.error(`Create failed: ${errorText(error)}`),
  });
  const statusMutation = useMutation({
    mutationFn: (status: string) => patchCaseStatus(selectedId!, status),
    onSuccess: (_, status) => {
      toast.success(`Case marked ${status}`);
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
      void queryClient.invalidateQueries({ queryKey: ["case", selectedId] });
    },
    onError: (error) => toast.error(`Status failed: ${errorText(error)}`),
  });
  const addMemberMutation = useMutation({
    mutationFn: () => addCaseMember(selectedId!, { object_type: memberType, object_id: Number(memberId), label: memberLabel, note: memberNote, tag: memberTag }),
    onSuccess: () => {
      toast.success("Member attached");
      setMemberId(""); setMemberLabel(""); setMemberNote(""); setMemberTag("");
      void queryClient.invalidateQueries({ queryKey: ["case", selectedId] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: (error) => toast.error(`Add member failed: ${errorText(error)}`),
  });
  const removeMemberMutation = useMutation({
    mutationFn: (mid: number) => removeCaseMember(selectedId!, mid),
    onSuccess: () => {
      toast.success("Member detached");
      void queryClient.invalidateQueries({ queryKey: ["case", selectedId] });
      void queryClient.invalidateQueries({ queryKey: ["cases"] });
    },
    onError: (error) => toast.error(`Remove failed: ${errorText(error)}`),
  });

  const cases = casesQuery.data ?? [];
  const detail = caseQuery.data;
  const statuses = STATUSES;

  return (
    <div className="console-shell registry-shell" data-testid="cases-page">
      <nav className="registry-nav">
        <Link to="/" className="registry-back"><ArrowLeft size={14} /> DARKFORCE CONSOLE</Link>
        <Link to="/evidence" className="registry-back" data-testid="cases-evidence-link"><FolderOpen size={14} /> EVIDENCE</Link>
        <span className="registry-title"><FolderOpen size={14} /> CASE FOLDERS &amp; OPS</span>
        <span className="mono registry-total">{cases.length} OPEN CASE{(cases.length === 1 ? "" : "S")}</span>
      </nav>
      <main className="console-main">
        <OpsAlerts alerts={alertsQuery.data ?? []} />
        <OpsPanel />

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "1rem", alignItems: "start" }}>
          <section className="console-panel" data-testid="cases-list-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker"><FolderOpen size={14} /> CASE FOLDERS</div>
                <div className="panel-subtitle">Select a folder to open its member ledger</div>
              </div>
              <div className="registry-filter-row">
                {["", ...statuses].map((status) => (
                  <button
                    type="button"
                    key={status || "all"}
                    className={`registry-chip ${statusFilter === status ? "active" : ""}`}
                    onClick={() => setStatusFilter(status)}
                  >
                    {status === "" ? "ALL" : status.toUpperCase()}
                  </button>
                ))}
              </div>
            </div>
            <div className="inventory-table-wrap">
              <table className="inventory-table">
                <thead><tr><th>ID</th><th>NAME</th><th>STATUS</th><th>OWNER</th><th>MEMBERS</th><th>UPDATED</th></tr></thead>
                <tbody>
                  {cases.map((c: CaseHeader) => (
                    <tr key={String(c.id)} onClick={() => setSelectedId(Number(c.id))} style={{ cursor: "pointer" }}>
                      <td className="mono">#{c.id}</td>
                      <td className="inventory-value">{getText(c.name)}</td>
                      <td><span className={`severity-dot ${c.status === "closed" ? "sev-low" : c.status === "watch" ? "sev-medium" : "sev-high"}`} />{getText(c.status, "open").toUpperCase()}</td>
                      <td className="mono">{getText(c.owner, "analyst")}</td>
                      <td className="mono">{Number(c.n_members ?? 0)}</td>
                      <td className="mono">{getText(c.updated_at, "—")}</td>
                    </tr>
                  ))}
                  {!cases.length && (
                    <tr><td colSpan={6} className="muted-text">
                      {casesQuery.isLoading
                        ? <><LoaderCircle className="animate-spin" size={13} /> Loading folders…</>
                        : casesQuery.error
                          ? <span className="query-error">{errorText(casesQuery.error)}</span>
                          : "No case folders yet."}
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          <section className="console-panel" data-testid="case-create-panel">
            <div className="panel-heading">
              <div>
                <div className="section-kicker"><Plus size={14} /> OPEN CASE FOLDER</div>
                <div className="panel-subtitle">Sandbox a persona, market or campaign for analyst review</div>
              </div>
            </div>
            <form onSubmit={(event) => { event.preventDefault(); if (name.trim()) createMutation.mutate(); }} className="stat-detail-table-stack">
              <Input value={name} onChange={(event) => setName(event.target.value)} placeholder="Case name (e.g. Carding syndicate 'XMR-Wallet')" aria-label="Case name" data-testid="case-name-input" />
              <div className="pipeline-buttons">
                <select value={createStatus} onChange={(event) => setCreateStatus(event.target.value)} className="console-select" aria-label="Initial status" data-testid="case-status-select">
                  {statuses.map((status) => <option key={status} value={status}>{status.toUpperCase()}</option>)}
                </select>
                <Input value={owner} onChange={(event) => setOwner(event.target.value)} placeholder="Owner" aria-label="Case owner" data-testid="case-owner-input" />
              </div>
              <Input value={notes} onChange={(event) => setNotes(event.target.value)} placeholder="Scope notes" aria-label="Case notes" data-testid="case-notes-input" />
              <div className="pipeline-buttons">
                <Button type="submit" disabled={!name.trim() || createMutation.isPending} data-testid="case-create-button">
                  {createMutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <FolderOpen size={13} />} Open folder
                </Button>
                {createMutation.error && <span className="query-error">{errorText(createMutation.error)}</span>}
              </div>
            </form>
          </section>
        </div>

        <section className="console-panel" data-testid="case-detail-panel">
          <div className="panel-heading">
            <div>
              <div className="section-kicker"><UserRound size={14} /> CASE MEMBER LEDGER</div>
              <div className="panel-subtitle">{detail ? `${getText(detail.name)} — ${getText(detail.status, "open").toUpperCase()} · ${(detail.members ?? []).length} member(s)` : "Select a folder above"}</div>
            </div>
            {detail && (
              <div className="pipeline-buttons">
                {statuses.map((status) => (
                  <Button
                    key={status}
                    variant="outline" size="sm"
                    disabled={detail.status === status || statusMutation.isPending}
                    onClick={() => statusMutation.mutate(status)}
                    data-testid={`case-status-${status}`}
                  >
                    {status.toUpperCase()}
                  </Button>
                ))}
              </div>
            )}
          </div>
          {selectedId && caseQuery.isLoading ? (
            <div className="query-state"><LoaderCircle className="animate-spin" size={16} /> Opening folder…</div>
          ) : selectedId && caseQuery.error ? (
            <div className="query-state query-error"><AlertTriangle size={16} /> {errorText(caseQuery.error)}</div>
          ) : detail ? (
            <div className="stat-detail-table-stack" data-testid="case-members-view">
              <form
                onSubmit={(event) => { event.preventDefault(); if (memberId.trim() && !Number.isNaN(Number(memberId))) addMemberMutation.mutate(); }}
                className="pipeline-buttons"
                style={{ flexWrap: "wrap" }}
              >
                <select value={memberType} onChange={(event) => setMemberType(event.target.value)} className="console-select" aria-label="Member object type" data-testid="member-type-select">
                  {MEMBER_TYPES.map((type) => <option key={type} value={type}>{type.toUpperCase()}</option>)}
                </select>
                <Input value={memberId} onChange={(event) => setMemberId(event.target.value)} placeholder="Object id" aria-label="Member object id" data-testid="member-id-input" />
                <Input value={memberLabel} onChange={(event) => setMemberLabel(event.target.value)} placeholder="Label" aria-label="Member label" data-testid="member-label-input" />
                <Input value={memberTag} onChange={(event) => setMemberTag(event.target.value)} placeholder="Tag" aria-label="Member tag" data-testid="member-tag-input" />
                <Input value={memberNote} onChange={(event) => setMemberNote(event.target.value)} placeholder="Note" aria-label="Member note" data-testid="member-note-input" />
                <Button type="submit" disabled={!memberId.trim() || Number.isNaN(Number(memberId)) || addMemberMutation.isPending} data-testid="member-add-button">
                  {addMemberMutation.isPending ? <LoaderCircle className="animate-spin" size={13} /> : <Plus size={13} />} Attach
                </Button>
              </form>
              <div className="inventory-table-wrap">
                <table className="inventory-table">
                  <thead><tr><th>TYPE</th><th>OBJECT</th><th>LABEL</th><th>TAG</th><th>ADDED BY</th><th>TS</th><th /></tr></thead>
                  <tbody>
                    {(detail.members ?? []).map((member) => (
                      <tr key={String(member.id)}>
                        <td className="mono">{getText(member.object_type, "—")}</td>
                        <td className="mono inventory-value">#{member.object_id}</td>
                        <td className="inventory-value">{getText(member.label, "—")}</td>
                        <td className="mono">{getText(member.tag, "—")}</td>
                        <td className="mono">{getText(member.added_by, "analyst")}</td>
                        <td className="mono">{getText(member.ts, "—")}</td>
                        <td>
                          <Button variant="ghost" size="icon-xs" disabled={removeMemberMutation.isPending} onClick={() => removeMemberMutation.mutate(Number(member.id))} data-testid={`member-remove-${member.id}`}>
                            <Trash2 size={13} />
                          </Button>
                        </td>
                      </tr>
                    ))}
                    {!(detail.members?.length) && <tr><td colSpan={7} className="muted-text">No members attached.</td></tr>}
                  </tbody>
                </table>
              </div>
              {getText(detail.notes) && <div className="evidence-text mono">{detail.notes}</div>}
            </div>
          ) : (
            <div className="query-state"><CircleHelp size={16} /> Select a case folder to manage its members.</div>
          )}
        </section>
      </main>
    </div>
  );
}