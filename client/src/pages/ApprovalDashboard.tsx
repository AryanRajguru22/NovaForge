import { useCallback, useEffect, useRef, useState, type ReactNode, useMemo } from "react";
import { Link, useNavigate } from "react-router-dom";
import { startAuthentication } from "@simplewebauthn/browser";
import type { PublicKeyCredentialRequestOptionsJSON } from "@simplewebauthn/types";
import { io, type Socket } from "socket.io-client";
import QRCode from "qrcode";
import { ApiError, apiGet, apiPost } from "../lib/api.js";

type Status = "PENDING" | "APPROVED" | "REJECTED" | "EXPIRED";

interface Person {
  id: string;
  name: string;
  email: string;
  role: string;
}

interface Policy {
  id: string;
  actionType: string;
  quorumType: string;
  minApprovals: number;
  eligibleRoles: string[];
  fallbackPolicyId: string | null;
  escalationTimeoutSec: number;
}

interface Vote {
  id: string;
  decision: "APPROVE" | "REJECT";
  deviceId: string;
  signature: string;
  timestamp: string;
  approver: Person;
}

interface ApprovalRequest {
  id: string;
  status: Status;
  expiresAt: string;
  policy: Policy;
  votes: Vote[];
}

interface Action {
  id: string;
  type: string;
  payload: unknown;
  status: Status;
  createdAt: string;
  requestedBy: Person;
  approvalRequest?: ApprovalRequest | null;
}

interface Approval {
  id: string;
  status: Status;
  expiresAt: string;
  action: Action;
  policy: Policy;
  votes: Vote[];
}

interface MeResponse {
  id: string;
  email: string;
  name: string;
  role: string;
  factors: {
    passkey: boolean;
    totp: boolean;
    recoveryCodes: number;
  };
}

const socketUrl = window.location.hostname === "localhost" ? "http://localhost:4000" : window.location.origin;

export default function ApprovalDashboard() {
  const navigate = useNavigate();
  const socketRef = useRef<Socket | null>(null);

  const [pendingApprovals, setPendingApprovals] = useState<Approval[]>([]);
  const [submittedActions, setSubmittedActions] = useState<Action[]>([]);
  const [approvalHistory, setApprovalHistory] = useState<Approval[]>([]);
  const [currentUser, setCurrentUser] = useState<MeResponse | null>(null);
  const [policies, setPolicies] = useState<Policy[]>([]);

  // New action modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createType, setCreateType] = useState("");
  const [createNote, setCreateNote] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);

  const [tab, setTab] = useState<"pending" | "submitted" | "history">("pending");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [directLookupApproval, setDirectLookupApproval] = useState<Approval | null>(null);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<string | null>(null);
  const [voting, setVoting] = useState<"APPROVE" | "REJECT" | null>(null);

  // QR Code Modal for second device approval
  const [showQRModal, setShowQRModal] = useState(false);
  const [qrCodeUrl, setQrCodeUrl] = useState<string | null>(null);

  const loadData = useCallback(async (isInitial = false) => {
    setError(null);
    try {
      // Fetch user profile
      const user = await apiGet<MeResponse>("/auth/me");
      setCurrentUser(user);

      // Fetch all datasets
      const [pending, submitted, history, availablePolicies] = await Promise.all([
        apiGet<Approval[]>("/approvals/pending"),
        apiGet<Action[]>("/actions"),
        apiGet<Approval[]>("/approvals/history"),
        apiGet<Policy[]>("/policies"),
      ]);

      setPendingApprovals(pending);
      setSubmittedActions(submitted);
      setApprovalHistory(history);
      setPolicies(availablePolicies);

      if (isInitial) {
        // Handle second-device URL deep linking / direct selection
        const queryParams = new URLSearchParams(window.location.search);
        const queryId = queryParams.get("id");

        if (queryId) {
          // Check if request is in pending
          const foundPending = pending.find((a) => a.id === queryId || a.action.id === queryId);
          if (foundPending) {
            setTab("pending");
            setSelectedId(foundPending.id);
            return;
          }

          // Check if request is in history
          const foundHistory = history.find((a) => a.id === queryId || a.action.id === queryId);
          if (foundHistory) {
            setTab("history");
            setSelectedId(foundHistory.id);
            return;
          }

          // Check if request is in submitted
          const foundSubmitted = submitted.find((a) => a.id === queryId || a.approvalRequest?.id === queryId);
          if (foundSubmitted) {
            setTab("submitted");
            setSelectedId(foundSubmitted.id);
            return;
          }

          // Not found in any list (maybe already voted on, or requested by someone else and resolved)
          // Attempt direct lookup via /actions/:id
          try {
            const data = await apiGet<{ action: Action; approvalRequest: ApprovalRequest | null }>(
              `/actions/${queryId}`,
            );
            if (data.action) {
              const approvalObj: Approval = data.approvalRequest
                ? {
                    id: data.approvalRequest.id,
                    status: data.approvalRequest.status,
                    expiresAt: data.approvalRequest.expiresAt,
                    action: data.action,
                    policy: data.approvalRequest.policy,
                    votes: data.approvalRequest.votes,
                  }
                : {
                    id: data.action.id,
                    status: data.action.status,
                    expiresAt: data.action.createdAt,
                    action: data.action,
                    policy: {
                      id: "",
                      actionType: data.action.type,
                      quorumType: "N_OF_M",
                      minApprovals: 0,
                      eligibleRoles: [],
                      fallbackPolicyId: null,
                      escalationTimeoutSec: 0,
                    },
                    votes: [],
                  };
              setDirectLookupApproval(approvalObj);
              setSelectedId(approvalObj.id);
              if (data.action.requestedBy.id === user.id) {
                setTab("submitted");
              } else if (approvalObj.status === "PENDING") {
                setTab("pending");
              } else {
                setTab("history");
              }
            }
          } catch (e) {
            console.error("Direct API lookup failed", e);
          }
        } else {
          // Select first pending request by default
          if (pending.length > 0) {
            setSelectedId(pending[0].id);
          }
        }
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate("/login");
      } else {
        setError(describeError(err));
      }
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  const refreshData = useCallback(async () => {
    try {
      const [pending, submitted, history] = await Promise.all([
        apiGet<Approval[]>("/approvals/pending"),
        apiGet<Action[]>("/actions"),
        apiGet<Approval[]>("/approvals/history"),
      ]);

      setPendingApprovals(pending);
      setSubmittedActions(submitted);
      setApprovalHistory(history);

      if (directLookupApproval) {
        try {
          const actionId = directLookupApproval.action.id;
          const data = await apiGet<{ action: Action; approvalRequest: ApprovalRequest | null }>(
            `/actions/${actionId}`,
          );
          if (data.action) {
            const approvalObj: Approval = data.approvalRequest
              ? {
                  id: data.approvalRequest.id,
                  status: data.approvalRequest.status,
                  expiresAt: data.approvalRequest.expiresAt,
                  action: data.action,
                  policy: data.approvalRequest.policy,
                  votes: data.approvalRequest.votes,
                }
              : {
                  id: data.action.id,
                  status: data.action.status,
                  expiresAt: data.action.createdAt,
                  action: data.action,
                  policy: {
                    id: "",
                    actionType: data.action.type,
                    quorumType: "N_OF_M",
                    minApprovals: 0,
                    eligibleRoles: [],
                    fallbackPolicyId: null,
                    escalationTimeoutSec: 0,
                  },
                  votes: [],
                };
            setDirectLookupApproval(approvalObj);
          }
        } catch (e) {
          console.error("Failed to refresh direct lookup item", e);
        }
      }
    } catch (err) {
      console.error("Failed to refresh dashboard data via socket trigger", err);
    }
  }, [directLookupApproval]);

  useEffect(() => {
    void loadData(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Set up real-time Socket.io updates
  useEffect(() => {
    const socket = io(socketUrl, { withCredentials: true });
    socketRef.current = socket;

    const handleSocketUpdate = () => {
      void refreshData();
    };

    socket.on("vote-cast", handleSocketUpdate);
    socket.on("status-update", handleSocketUpdate);
    socket.on("escalated", handleSocketUpdate);

    return () => {
      socket.disconnect();
      socketRef.current = null;
    };
  }, [refreshData]);

  // Map the selected ID to a resolved approval object
  const selectedApproval = useMemo(() => {
    if (!selectedId) return null;

    if (directLookupApproval && (directLookupApproval.id === selectedId || directLookupApproval.action.id === selectedId)) {
      return directLookupApproval;
    }

    if (tab === "pending") {
      return pendingApprovals.find((a) => a.id === selectedId) || null;
    } else if (tab === "history") {
      return approvalHistory.find((a) => a.id === selectedId) || null;
    } else {
      const action = submittedActions.find((a) => a.id === selectedId || a.approvalRequest?.id === selectedId);
      if (!action) return null;
      if (!action.approvalRequest) {
        return {
          id: action.id,
          status: action.status,
          expiresAt: action.createdAt,
          action: action,
          policy: {
            id: "",
            actionType: action.type,
            quorumType: "N_OF_M",
            minApprovals: 0,
            eligibleRoles: [],
            fallbackPolicyId: null,
            escalationTimeoutSec: 0,
          },
          votes: [],
        };
      }
      return {
        id: action.approvalRequest.id,
        status: action.approvalRequest.status,
        expiresAt: action.approvalRequest.expiresAt,
        action: action,
        policy: action.approvalRequest.policy,
        votes: action.approvalRequest.votes,
      };
    }
  }, [tab, selectedId, pendingApprovals, submittedActions, approvalHistory, directLookupApproval]);

  // Join the Socket.io room for the currently selected request (for live updates & second-device sync)
  useEffect(() => {
    if (selectedApproval?.id) {
      socketRef.current?.emit("join-challenge", selectedApproval.id);
    }
  }, [selectedApproval?.id]);

  async function castVote(decision: "APPROVE" | "REJECT") {
    if (!selectedApproval) return;
    setError(null);
    setStatus(null);
    setVoting(decision);
    try {
      setStatus("Requesting approval challenge…");
      const options = await apiPost<PublicKeyCredentialRequestOptionsJSON>(
        `/approvals/${selectedApproval.id}/options`,
        {},
      );

      setStatus("Waiting for your device (passkey key verification)…");
      const response = await startAuthentication(options);

      setStatus("Submitting and verifying signature…");
      const result = await apiPost<{ requestStatus: Status }>(
        `/approvals/${selectedApproval.id}/vote`,
        { decision, response },
      );

      setStatus(
        result.requestStatus === "PENDING"
          ? "Vote cast successfully. Awaiting additional approvers."
          : `Request has been ${result.requestStatus.toLowerCase()}.`,
      );
      void refreshData();
    } catch (err) {
      setError(describeError(err));
      setStatus(null);
    } finally {
      setVoting(null);
    }
  }

  async function generateSecondDeviceLink() {
    if (!selectedApproval) return;
    try {
      const shareUrl = `${window.location.origin}/approvals?id=${selectedApproval.id}`;
      const codeUrl = await QRCode.toDataURL(shareUrl, {
        margin: 2,
        width: 256,
        color: {
          dark: "#161110", // iron-950
          light: "#f4ead9", // parchment-100
        },
      });
      setQrCodeUrl(codeUrl);
      setShowQRModal(true);
    } catch (err) {
      setError("Failed to initialize second device flow. QR generation failed.");
    }
  }

  async function submitCreate() {
    if (!createType.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      const created = await apiPost<{ action: Action; approvalRequest: { id: string } }>("/actions", {
        type: createType.trim(),
        payload: { note: createNote.trim() || undefined },
      });
      setShowCreateModal(false);
      setCreateType("");
      setCreateNote("");
      setTab("submitted");
      setSelectedId(created.action.id);
      await loadData();
    } catch (err) {
      setCreateError(describeError(err));
    } finally {
      setCreating(false);
    }
  }

  if (loading) {
    return (
      <PageFrame>
        <div className="flex min-h-[400px] flex-col items-center justify-center space-y-4">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-ash-400 border-t-parchment-100"></div>
          <p className="text-sm text-ash-400">Loading your approval workspace…</p>
        </div>
      </PageFrame>
    );
  }

  return (
    <PageFrame>
      {/* Upper Metrics / Header */}
      <div className="flex flex-col gap-5 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="eyebrow">Workspace</p>
          <h1 className="font-display mt-1 text-3xl text-parchment-100">Approval dashboard</h1>
          <p className="font-serif mt-1 text-sm text-ash-400">
            Review sensitive actions, cast passkey-signed decisions, and manage policies.
          </p>
        </div>
        <div className="flex gap-3">
          <button
            type="button"
            onClick={() => {
              setCreateError(null);
              setShowCreateModal(true);
            }}
            className="btn-primary"
          >
            New action
          </button>
          <button
            type="button"
            onClick={() => {
              setLoading(true);
              void loadData();
            }}
            className="btn-secondary"
          >
            Refresh Data
          </button>
        </div>
      </div>

      {error && <Notice kind="error">{error}</Notice>}
      {status && <Notice>{status}</Notice>}

      {/* Metric summary boxes */}
      <div className="grid gap-3 grid-cols-1 sm:grid-cols-3">
        <Metric
          label="Awaiting my vote"
          value={pendingApprovals.length}
          active={tab === "pending"}
          onClick={() => {
            setTab("pending");
            setSelectedId(pendingApprovals[0]?.id || null);
          }}
        />
        <Metric
          label="My submitted actions"
          value={submittedActions.length}
          active={tab === "submitted"}
          onClick={() => {
            setTab("submitted");
            setSelectedId(submittedActions[0]?.id || null);
          }}
        />
        <Metric
          label="Resolved history"
          value={approvalHistory.length}
          active={tab === "history"}
          onClick={() => {
            setTab("history");
            setSelectedId(approvalHistory[0]?.id || null);
          }}
        />
      </div>

      {/* Grid container for left column lists and right column detail inspection */}
      <div className="grid gap-6 lg:grid-cols-[minmax(0,0.9fr)_minmax(0,1.1fr)]">
        {/* Left lists section */}
        <section className="rounded border border-iron-800 bg-iron-900 overflow-hidden flex flex-col">
          {/* Tab headers */}
          <div className="flex border-b border-iron-800 bg-iron-900/50">
            <button
              type="button"
              onClick={() => {
                setTab("pending");
                setSelectedId(pendingApprovals[0]?.id || null);
              }}
              className={`flex-1 py-3 text-center text-sm font-medium border-b-2 transition-colors ${
                tab === "pending"
                  ? "border-ember-500 text-parchment-100 bg-iron-800/40"
                  : "border-transparent text-ash-400 hover:text-parchment-100"
              }`}
            >
              Pending ({pendingApprovals.length})
            </button>
            <button
              type="button"
              onClick={() => {
                setTab("submitted");
                setSelectedId(submittedActions[0]?.id || null);
              }}
              className={`flex-1 py-3 text-center text-sm font-medium border-b-2 transition-colors ${
                tab === "submitted"
                  ? "border-ember-500 text-parchment-100 bg-iron-800/40"
                  : "border-transparent text-ash-400 hover:text-parchment-100"
              }`}
            >
              My Actions ({submittedActions.length})
            </button>
            <button
              type="button"
              onClick={() => {
                setTab("history");
                setSelectedId(approvalHistory[0]?.id || null);
              }}
              className={`flex-1 py-3 text-center text-sm font-medium border-b-2 transition-colors ${
                tab === "history"
                  ? "border-ember-500 text-parchment-100 bg-iron-800/40"
                  : "border-transparent text-ash-400 hover:text-parchment-100"
              }`}
            >
              History ({approvalHistory.length})
            </button>
          </div>

          {/* List content body */}
          <div className="divide-y divide-iron-800 max-h-[600px] overflow-y-auto">
            {tab === "pending" && (
              pendingApprovals.length === 0 ? (
                <Empty title="No pending approvals" text="You have no actions waiting for your signature." />
              ) : (
                pendingApprovals.map((item) => (
                  <ListButton
                    key={item.id}
                    active={selectedId === item.id}
                    onClick={() => setSelectedId(item.id)}
                    title={item.action.type}
                    subtitle={`Requested by ${item.action.requestedBy.name}`}
                    badgeStatus={item.status}
                    dateLabel={`Expires: ${formatDate(item.expiresAt)}`}
                  />
                ))
              )
            )}

            {tab === "submitted" && (
              submittedActions.length === 0 ? (
                <Empty title="No submitted actions" text="You haven't requested any sensitive actions yet." />
              ) : (
                submittedActions.map((item) => (
                  <ListButton
                    key={item.id}
                    active={selectedId === item.id}
                    onClick={() => setSelectedId(item.id)}
                    title={item.type}
                    subtitle={`Submitted by you`}
                    badgeStatus={item.status}
                    dateLabel={`Requested: ${formatDate(item.createdAt)}`}
                  />
                ))
              )
            )}

            {tab === "history" && (
              approvalHistory.length === 0 ? (
                <Empty title="No approval history" text="No resolved or voted actions found." />
              ) : (
                approvalHistory.map((item) => (
                  <ListButton
                    key={item.id}
                    active={selectedId === item.id}
                    onClick={() => setSelectedId(item.id)}
                    title={item.action.type}
                    subtitle={`Requested by ${item.action.requestedBy.name}`}
                    badgeStatus={item.status}
                    dateLabel={`Voted / Closed: ${formatDate(item.expiresAt)}`}
                  />
                ))
              )
            )}
          </div>
        </section>

        {/* Right details section */}
        <section className="rounded border border-iron-800 bg-iron-900 p-5 flex flex-col justify-between min-h-[500px]">
          {!selectedApproval ? (
            <div className="flex flex-col items-center justify-center h-full my-auto text-center space-y-2">
              <svg className="w-12 h-12 text-iron-600" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
              </svg>
              <h3 className="text-base font-medium text-ash-300">No item selected</h3>
              <p className="text-sm text-ash-400 max-w-xs">Select a request from the left list to review detailed policies, votes, and sign decisions.</p>
            </div>
          ) : (
            <ApprovalDetailsPanel
              approval={selectedApproval}
              currentUser={currentUser}
              voting={voting}
              onVote={castVote}
              onSecondDevice={generateSecondDeviceLink}
              isPendingTab={tab === "pending" && selectedApproval.status === "PENDING"}
            />
          )}
        </section>
      </div>

      {/* Second Device QR Modal */}
      {showQRModal && selectedApproval && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-iron-950/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded border border-iron-800 bg-iron-900 p-6 space-y-6 text-center shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div>
              <h2 className="font-display text-xl text-parchment-100">Approve on another device</h2>
              <p className="text-xs text-ash-400 mt-1">Scan or share this link to sign using a secondary device's passkey</p>
            </div>

            {qrCodeUrl && (
              <div className="flex justify-center rounded bg-white p-3 mx-auto w-fit">
                <img src={qrCodeUrl} alt="QR Code Link to Approval Request" className="w-48 h-48" />
              </div>
            )}

            <div className="space-y-2">
              <button
                type="button"
                onClick={async () => {
                  const shareUrl = `${window.location.origin}/approvals?id=${selectedApproval.id}`;
                  await navigator.clipboard.writeText(shareUrl).catch(() => undefined);
                  alert("Link copied to clipboard!");
                }}
                className="w-full rounded border border-iron-700 bg-iron-950 px-3 py-2 text-xs font-medium text-ash-300 hover:bg-iron-800 transition-colors"
              >
                Copy workspace link
              </button>
              <p className="text-[10px] text-ash-400 max-w-xs mx-auto leading-relaxed">
                Make sure you are logged in on the second device. Tapping approval there will automatically update this screen in real-time.
              </p>
            </div>

            <button
              type="button"
              onClick={() => {
                setShowQRModal(false);
                setQrCodeUrl(null);
              }}
              className="btn-primary w-full"
            >
              Done / Close
            </button>
          </div>
        </div>
      )}

      {/* New Action Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-iron-950/80 p-4 backdrop-blur-sm">
          <div className="w-full max-w-sm rounded border border-iron-800 bg-iron-900 p-6 space-y-5 shadow-2xl animate-in fade-in zoom-in-95 duration-150">
            <div>
              <h2 className="font-display text-xl text-parchment-100">Request a sensitive action</h2>
              <p className="mt-1 text-xs text-ash-400">
                Creates a new action and routes it through whichever policy matches the action type.
              </p>
            </div>

            {createError && <Notice kind="error">{createError}</Notice>}

            <div className="space-y-2">
              <label className="text-sm text-ash-300" htmlFor="create-action-type">
                Action type
              </label>
              <input
                id="create-action-type"
                list="known-action-types"
                value={createType}
                onChange={(event) => setCreateType(event.target.value)}
                placeholder="e.g. TRANSFER_FUNDS"
                className="w-full rounded border border-iron-700 bg-iron-950 px-3 py-2 text-sm text-parchment-100 focus:border-ash-400 focus:outline-none"
              />
              <datalist id="known-action-types">
                {policies.map((policy) => (
                  <option key={policy.id} value={policy.actionType} />
                ))}
              </datalist>
              {policies.length === 0 ? (
                <p className="text-xs text-amber-300">
                  No policies exist yet — create one on the Policies page first, or this will fail with
                  "no approval policy configured."
                </p>
              ) : (
                <p className="text-xs text-ash-400">
                  Must match an existing policy's action type exactly (see suggestions above).
                </p>
              )}
            </div>

            <div className="space-y-2">
              <label className="text-sm text-ash-300" htmlFor="create-action-note">
                Note (optional)
              </label>
              <textarea
                id="create-action-note"
                value={createNote}
                onChange={(event) => setCreateNote(event.target.value)}
                rows={3}
                placeholder="Context for approvers — becomes the action payload."
                className="w-full rounded border border-iron-700 bg-iron-950 px-3 py-2 text-sm text-parchment-100 focus:border-ash-400 focus:outline-none"
              />
            </div>

            <div className="flex gap-3">
              <button
                type="button"
                disabled={creating || !createType.trim()}
                onClick={() => void submitCreate()}
                className="btn-primary flex-1"
              >
                {creating ? "Submitting…" : "Submit for approval"}
              </button>
              <button
                type="button"
                onClick={() => setShowCreateModal(false)}
                className="rounded border border-iron-700 bg-iron-950 px-3 py-2 text-sm text-ash-300 hover:bg-iron-800 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </PageFrame>
  );
}

function PageFrame({ children }: { children: ReactNode }) {
  return (
    <main className="min-h-screen p-5 sm:p-8">
      <div className="mx-auto max-w-6xl space-y-6">
        <nav className="ledger-rule flex items-center gap-5 pb-4 text-sm text-ash-400">
          <Link to="/approvals" className="font-semibold text-parchment-100">
            Approvals
          </Link>
          <Link to="/policies" className="link-quiet">
            Policies
          </Link>
          <Link to="/settings" className="link-quiet">
            Security Settings
          </Link>
        </nav>
        {children}
      </div>
    </main>
  );
}

function Metric({
  label,
  value,
  active,
  onClick,
}: {
  label: string;
  value: number;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`text-left w-full rounded border p-4 transition-all ${
        active
          ? "border-ember-500/60 bg-iron-900 shadow-[0_0_0_1px_rgba(255,106,52,0.15)]"
          : "border-iron-700 bg-iron-900/40 hover:bg-iron-900"
      }`}
    >
      <p className="eyebrow">{label}</p>
      <p className="font-display mt-2 text-3xl text-parchment-100">{value}</p>
    </button>
  );
}

function ListButton({
  active,
  onClick,
  title,
  subtitle,
  badgeStatus,
  dateLabel,
}: {
  active: boolean;
  onClick: () => void;
  title: string;
  subtitle: string;
  badgeStatus: Status;
  dateLabel: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={`w-full p-4 text-left border-l-2 transition-all flex flex-col justify-between gap-2 hover:bg-iron-800/40 ${
        active ? "bg-iron-800/60 border-ember-500" : "border-transparent"
      }`}
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="font-medium text-sm text-parchment-100 line-clamp-1">{title}</p>
          <p className="mt-0.5 text-xs text-ash-400 line-clamp-1">{subtitle}</p>
        </div>
        <Stamp status={badgeStatus} />
      </div>
      <p className="text-[10px] text-ash-400 font-mono self-start">{dateLabel}</p>
    </button>
  );
}

/* The Seal: every request status rendered as a struck mark rather than a soft
   pill badge. PENDING glows like it's still in the fire; APPROVED strikes
   into a closed ring, once, the moment quorum lands. */
function Stamp({ status, size = "sm" }: { status: Status; size?: "sm" | "lg" }) {
  const isLarge = size === "lg";
  const ring: Record<Status, string> = {
    PENDING: "border-ember-500 text-ember-400 animate-pulse",
    APPROVED: "border-temper-400 text-temper-300 seal-strike",
    REJECTED: "border-rust-500 text-rust-400",
    EXPIRED: "border-iron-600 text-ash-400",
  };
  return (
    <span
      key={status}
      className={`inline-flex items-center justify-center rounded-full border-2 font-mono font-semibold uppercase tracking-wider ${ring[status]} ${
        isLarge ? "h-16 w-16 text-[10px]" : "h-6 px-2 text-[9px] border"
      }`}
    >
      {isLarge ? status.slice(0, 4) : status.toLowerCase()}
    </span>
  );
}

function Detail({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p className="eyebrow">{label}</p>
      <p className="mt-1 text-sm font-medium text-parchment-100">{value}</p>
    </div>
  );
}

function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="p-8 text-center space-y-1">
      <p className="font-display text-lg text-parchment-100">{title}</p>
      <p className="text-xs text-ash-400">{text}</p>
    </div>
  );
}

function Notice({ children, kind }: { children: ReactNode; kind?: "error" }) {
  return (
    <div
      className={`rounded border p-4 text-sm flex gap-3 items-center ${
        kind === "error"
          ? "border-rust-500/40 bg-rust-500/10 text-rust-400"
          : "border-iron-700 bg-iron-900 text-ash-300"
      }`}
    >
      <span className="flex-1 leading-normal font-medium">{children}</span>
    </div>
  );
}

function ApprovalDetailsPanel({
  approval,
  currentUser,
  voting,
  onVote,
  onSecondDevice,
  isPendingTab,
}: {
  approval: Approval;
  currentUser: MeResponse | null;
  voting: "APPROVE" | "REJECT" | null;
  onVote: (decision: "APPROVE" | "REJECT") => void;
  onSecondDevice: () => void;
  isPendingTab: boolean;
}) {
  const isRequester = approval.action.requestedBy.id === currentUser?.id;
  const hasUserVoted = approval.votes.some((vote) => vote.approver.id === currentUser?.id);
  const isEligibleRole = currentUser
    ? approval.policy.eligibleRoles.includes(currentUser.role)
    : false;

  // Decide if the current user can vote right now
  const canVote = isPendingTab && !isRequester && !hasUserVoted && isEligibleRole;
  const isActionResolved = approval.status !== "PENDING";

  return (
    <div className="space-y-6 flex flex-col justify-between h-full">
      <div className="space-y-6">
        {/* Detail Panel Header */}
        <div className="flex flex-wrap items-start justify-between gap-4 border-b border-iron-800 pb-5">
          <div className="space-y-1">
            <p className="text-xs text-ash-400 font-medium uppercase tracking-wider">Sensitive Action</p>
            <h2 className="font-display text-2xl text-parchment-100">{approval.action.type}</h2>
            <p className="text-xs text-ash-400">Action ID: {approval.action.id}</p>
          </div>
          <div className="flex flex-col items-end gap-2">
            <Stamp status={approval.status} size="lg" />
          </div>
        </div>

        {/* Core details grid */}
        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2">
          <Detail label="Requested by" value={`${approval.action.requestedBy.name} (${approval.action.requestedBy.email})`} />
          <Detail label="Request Date" value={formatDate(approval.action.createdAt)} />
          <Detail label="Expires / Resolved" value={formatDate(approval.expiresAt)} />
          <Detail
            label="Fallback policy"
            value={
              approval.policy.fallbackPolicyId
                ? "Active escalation fallback chain"
                : "None (expires on timeout)"
            }
          />
        </div>

        {/* Payload display */}
        <div className="space-y-2">
          <p className="text-xs text-ash-400 font-medium uppercase tracking-wider">Payload</p>
          <pre className="max-h-48 overflow-y-auto rounded border border-iron-800 bg-iron-950 p-4 font-mono text-xs text-ash-300 leading-relaxed scrollbar-thin">
            {JSON.stringify(approval.action.payload, null, 2)}
          </pre>
        </div>

        {/* Approval Policy rules */}
        <div className="border-t border-iron-800 pt-5 space-y-3">
          <h3 className="font-semibold text-sm text-parchment-100">Approval policy</h3>
          <div className="grid gap-4 grid-cols-1 sm:grid-cols-2">
            <Detail
              label="Quorum criteria"
              value={
                approval.policy.quorumType === "ROLE_BASED"
                  ? `Requires approval from all eligible roles`
                  : `Requires minimum ${approval.policy.minApprovals} vote${
                      approval.policy.minApprovals === 1 ? "" : "s"
                    } (N of M)`
              }
            />
            <Detail
              label="Eligible roles"
              value={
                approval.policy.eligibleRoles.length === 0
                  ? "No roles specified"
                  : approval.policy.eligibleRoles.map((role) => role.replace(/_/g, " ")).join(", ")
              }
            />
            <Detail label="Quorum type" value={approval.policy.quorumType.replace(/_/g, " ")} />
            <Detail label="Escalation timeout" value={`${approval.policy.escalationTimeoutSec} seconds`} />
          </div>
        </div>

        {/* Votes listing & crypto assertions */}
        <div className="border-t border-iron-800 pt-5 space-y-3">
          <h3 className="font-semibold text-sm text-parchment-100">Cryptographically Signed Votes</h3>
          {approval.votes.length === 0 ? (
            <p className="text-xs text-ash-400 leading-relaxed">No votes recorded yet for this request.</p>
          ) : (
            <ul className="space-y-3">
              {approval.votes.map((vote) => (
                <li
                  key={vote.id}
                  className="rounded border border-iron-800 bg-iron-950 p-4 space-y-2 text-xs"
                >
                  <div className="flex justify-between items-start">
                    <div>
                      <p className="font-semibold text-parchment-100">{vote.approver.name}</p>
                      <p className="text-ash-400 mt-0.5">{vote.approver.email} · {vote.approver.role.replace(/_/g, " ")}</p>
                    </div>
                    <span
                      className={`rounded px-1.5 py-0.5 font-bold uppercase tracking-wider text-[9px] ${
                        vote.decision === "APPROVE"
                          ? "bg-temper-400/10 text-temper-300"
                          : "bg-rust-400/10 text-rust-400"
                      }`}
                    >
                      {vote.decision.toLowerCase()}d
                    </span>
                  </div>

                  {/* WebAuthn assertion signature trail */}
                  <div className="border-t border-iron-800/80 pt-2 grid gap-1 grid-cols-1 font-mono text-[10px] text-ash-400">
                    <p className="truncate">
                      <span className="text-ash-400">Device ID:</span> {vote.deviceId}
                    </p>
                    <p className="break-all font-semibold">
                      <span className="text-ash-400 font-normal">Signature:</span>{" "}
                      {vote.signature.substring(0, 32)}… [WebAuthn Asserted]
                    </p>
                    <p className="text-[9px] text-ash-400">
                      Verified at {formatDate(vote.timestamp)}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Interactive buttons or informational notices */}
      <div className="border-t border-iron-800 pt-5 space-y-4">
        {canVote ? (
          <div className="flex flex-col gap-3 sm:flex-row">
            <button
              type="button"
              disabled={voting !== null}
              onClick={() => onVote("APPROVE")}
              className="flex-1 rounded bg-temper-400 px-4 py-2 text-sm font-semibold text-iron-950 hover:bg-temper-300 disabled:opacity-50 transition-colors"
            >
              {voting === "APPROVE" ? "Casting approval…" : "Approve with passkey"}
            </button>
            <button
              type="button"
              disabled={voting !== null}
              onClick={() => onVote("REJECT")}
              className="flex-1 rounded border border-rust-500/70 px-4 py-2 text-sm font-semibold text-rust-400 hover:bg-rust-500/10 disabled:opacity-50 transition-colors"
            >
              {voting === "REJECT" ? "Casting rejection…" : "Reject with passkey"}
            </button>
            <button
              type="button"
              onClick={onSecondDevice}
              className="rounded border border-iron-700 bg-iron-900 px-4 py-2 text-sm text-parchment-100 hover:bg-iron-800 transition-colors"
            >
              Approve on another device
            </button>
          </div>
        ) : (
          <div className="rounded bg-iron-900/60 p-4 border border-iron-800 text-xs text-ash-400 text-center">
            {isActionResolved ? (
              <p>This approval request is completed and is no longer accepting votes.</p>
            ) : isRequester ? (
              <p>You are the requester of this sensitive action and cannot approve or reject your own action.</p>
            ) : hasUserVoted ? (
              <p className="text-temper-400">Your passkey-signed vote has been cryptographically recorded.</p>
            ) : !isEligibleRole ? (
              <p>
                Your role ({currentUser?.role.replace(/_/g, " ")}) is not authorized to sign decisions for
                this policy.
              </p>
            ) : (
              <p>Voting is unavailable for this request.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function formatDate(value: string) {
  if (!value) return "";
  return new Date(value).toLocaleString();
}

function describeError(err: unknown): string {
  if (err instanceof ApiError) return err.message;
  if (err instanceof Error) {
    if (err.name === "NotAllowedError") {
      return "Passkey signature flow cancelled or timed out.";
    }
    return err.message;
  }
  return "Something went wrong.";
}
