import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const RA_HMAC_SECRET = Deno.env.get("RA_HMAC_SECRET") ?? "";
const SESSION_SECRET = Deno.env.get("SESSION_SECRET") ?? "";
const ADMIN_ACCESS_CODE = Deno.env.get("ADMIN_ACCESS_CODE") ?? "";
const ROSTER_SETUP_KEY = Deno.env.get("ROSTER_SETUP_KEY") ?? "";
const ADMIN_NAME = "david chrispim de melo";
const DAY_MS = 24 * 60 * 60 * 1000;

const categories = [
  { id: "iconico", name: "Mais Bonito(a)" },
  { id: "mais_fofoqueiro", name: "Mais Fofoqueiro(a)" },
  { id: "mais_sem_filtro", name: "MMais Feio(a)" },
  { id: "mais_dramatico", name: "Mais Dramático(a)" },
  { id: "mais_polemico", name: "Mais Polêmico(a)" },
  { id: "mais_enrolado", name: "Mais Enrolado(a)" },
  { id: "mais_mao_de_vaca", name: "Mais “Mão de Vaca”" },
  { id: "mais_sumido", name: "Mais Sumido(a)" },
  { id: "cabeca_de_vento", name: "Mais Cabeça de Vento" },
  { id: "mais_gado", name: "Mais “Gado(a)”" },
  { id: "mais_carente", name: "Mais Carente" },
  { id: "mais_intenso", name: "Mais Intenso(a)" },
  { id: "mais_celular", name: "Mais Viciado(a) no Celular" },
  { id: "mais_preguicoso", name: "Mais Preguiçoso(a)" },
  { id: "pai_mae_turma", name: "Mais “Pai/Mãe da Turma”" },
  { id: "mais_cringe", name: "Mais Cringe" },
  { id: "mais_estiloso", name: "MMais Feio(a)" },
  { id: "mais_cola", name: "Mais “Cola”" },
  { id: "mais_gente_boa", name: "Mais Gente Boa" },
  { id: "mais_sortudo", name: "Mais Sortudo(a)" },
  { id: "mais_entrosa", name: "Mais Entrosa" },
];
const categoryIds = new Set(categories.map((c) => c.id));
const supabase = createClient(SUPABASE_URL, SERVICE_KEY, {
  auth: { persistSession: false, autoRefreshToken: false },
});

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}
function normalizeName(value: unknown): string {
  return String(value ?? "").normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLocaleLowerCase("pt-BR").replace(/[^a-z0-9 ]/g, " ").replace(/\s+/g, " ").trim();
}
function normalizeRa(value: unknown): string {
  return String(value ?? "").replace(/\s+/g, "").toUpperCase().replace(/SP$/i, "");
}
function toHex(bytes: ArrayBuffer): string {
  return Array.from(new Uint8Array(bytes)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function signHex(secret: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return toHex(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message)));
}
function base64url(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function fromBase64url(input: string): string {
  const base = input.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base + "=".repeat((4 - base.length % 4) % 4);
  const raw = atob(padded);
  return new TextDecoder().decode(Uint8Array.from(raw, (c) => c.charCodeAt(0)));
}
async function createSession(payload: Record<string, unknown>): Promise<string> {
  const body = base64url(JSON.stringify({ ...payload, exp: Date.now() + 12 * 60 * 60 * 1000 }));
  return `${body}.${await signHex(SESSION_SECRET, body)}`;
}
async function verifySession(token: unknown): Promise<any> {
  if (typeof token !== "string" || !token.includes(".")) throw new Error("Sua sessão expirou. Entre novamente.");
  const [body, signature] = token.split(".", 2);
  const expected = await signHex(SESSION_SECRET, body);
  if (!constantTimeEqual(signature, expected)) throw new Error("Sessão inválida. Entre novamente.");
  const payload = JSON.parse(fromBase64url(body));
  if (!payload.exp || payload.exp < Date.now() || !payload.sid) throw new Error("Sua sessão expirou. Entre novamente.");
  return payload;
}
function constantTimeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
async function getDeadline(): Promise<string | null> {
  const { data, error } = await supabase.from("awards_config").select("deadline").eq("id", 1).single();
  if (error) throw error;
  return data?.deadline ?? null;
}
async function getPersonalMessage(studentId: string): Promise<string | null> {
  const { data, error } = await supabase.from("student_messages")
    .select("message").eq("student_id", studentId).maybeSingle();
  // Se a tabela ainda não foi configurada, a votação continua funcionando; o organizador
  // pode aplicar o script privado dos recados e publicar a função novamente.
  if (error) {
    console.error("Não foi possível carregar o recado individual:", error.message);
    return null;
  }
  return typeof data?.message === "string" ? data.message : null;
}
function getPhase(deadline: string | null, nowMs = Date.now()): "not_started" | "general" | "final" | "closed" {
  if (!deadline) return "not_started";
  const deadlineMs = new Date(deadline).getTime();
  if (nowMs >= deadlineMs) return "closed";
  if (nowMs < deadlineMs - 10 * DAY_MS) return "general";
  return "final";
}
function released(deadline: string | null): boolean {
  return getPhase(deadline) === "closed";
}
async function getAggregate(phase: "general" | "final" | null = null) {
  const [{ data: students, error: studentsError }, { data: allBallots, error: ballotsError }] = await Promise.all([
    supabase.from("students").select("id, full_name"),
    supabase.from("ballots").select("votes, phase"),
  ]);
  if (studentsError) throw studentsError;
  if (ballotsError) throw ballotsError;
  const people = (students ?? []).map((s: any) => ({ id: String(s.id), name: String(s.full_name) }));
  const names = new Map<string, string>(people.map((s: any) => [s.id, s.name] as [string, string]));
  const ballots = (allBallots ?? []).filter((b: any) => !phase || b.phase === phase);
  const counts = new Map<string, Map<string, number>>();
  for (const category of categories) {
    counts.set(category.id, new Map(people.map((person: any) => [person.id, 0] as [string, number])));
  }
  for (const ballot of ballots) {
    const votes = ballot.votes && typeof ballot.votes === "object" ? ballot.votes as Record<string, unknown> : {};
    for (const [categoryId, selection] of Object.entries(votes)) {
      if (!categoryIds.has(categoryId)) continue;
      const tally = counts.get(categoryId)!;
      // Compatibilidade: cédulas antigas guardavam apenas um ID por categoria (1 ponto).
      if (typeof selection === "string") {
        if (names.has(selection)) tally.set(selection, (tally.get(selection) ?? 0) + 1);
        continue;
      }
      if (!selection || typeof selection !== "object" || Array.isArray(selection)) continue;
      const ranked = selection as Record<string, unknown>;
      const first = typeof ranked.first === "string" ? ranked.first : null;
      const second = typeof ranked.second === "string" ? ranked.second : null;
      if (first && names.has(first)) tally.set(first, (tally.get(first) ?? 0) + 1);
      if (second && names.has(second) && second !== first) tally.set(second, (tally.get(second) ?? 0) + 0.5);
    }
  }
  const results = categories.map((category) => ({
    categoryId: category.id,
    categoryName: category.name,
    votes: Array.from(counts.get(category.id)!.entries())
      .map(([id, count]) => ({ id, name: names.get(id)!, count }))
      .sort((a, b) => b.count - a.count || a.name.localeCompare(b.name, "pt-BR")),
  }));
  return { results, totalBallots: ballots.length, totalStudents: people.length };
}
async function getFinalistsByCategory(): Promise<Record<string, Array<{ id: string; name: string; count: number }>>> {
  const general = await getAggregate("general");
  const finalists: Record<string, Array<{ id: string; name: string; count: number }>> = {};
  for (const category of general.results) {
    // Ordenação determinística: votos decrescentes; em empate, ordem alfabética.
    finalists[category.categoryId] = category.votes.slice(0, 4);
  }
  return finalists;
}
async function getPhaseBallotCounts() {
  const { data, error } = await supabase.from("ballots").select("phase");
  if (error) throw error;
  return (data ?? []).reduce((counts: { general: number; final: number }, ballot: any) => {
    if (ballot.phase === "general") counts.general++;
    if (ballot.phase === "final") counts.final++;
    return counts;
  }, { general: 0, final: 0 });
}
async function authenticatedSession(token: unknown, requireAdmin = false) {
  const session = await verifySession(token);
  if (requireAdmin && session.admin !== true) throw new Error("Acesso restrito à administração.");
  return session;
}

Deno.serve(async (req: Request) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });
  if (req.method !== "POST") return json({ error: "Método não permitido." }, 405);
  if (!SUPABASE_URL || !SERVICE_KEY || !RA_HMAC_SECRET || !SESSION_SECRET) {
    return json({ error: "A configuração do servidor está incompleta. Avise o organizador." }, 500);
  }
  try {
    const body = await req.json();
    const action = String(body.action ?? "");

    if (action === "setup_roster") {
      if (!ROSTER_SETUP_KEY || !constantTimeEqual(String(body.setupKey ?? ""), ROSTER_SETUP_KEY)) return json({ error: "Chave de configuração inválida." }, 401);
      if (!Array.isArray(body.roster) || body.roster.length < 1 || body.roster.length > 100) return json({ error: "Lista de participantes inválida." }, 400);
      const { data: existing, error: countError } = await supabase.from("students").select("id").limit(1);
      if (countError) throw countError;
      if (existing && existing.length) return json({ error: "A lista já foi importada. A importação inicial só pode ser feita uma vez." }, 409);
      const rows = [];
      const seen = new Set<string>();
      for (const raw of body.roster) {
        const fullName = String(raw?.full_name ?? "").trim();
        const normalized = normalizeName(fullName);
        const ra = normalizeRa(raw?.ra);
        if (!fullName || !normalized || !/^\d{10,15}X?$/.test(ra) || seen.has(normalized)) return json({ error: "A lista contém nome duplicado ou registro inválido. Nada foi importado." }, 400);
        seen.add(normalized);
        rows.push({
          full_name: fullName,
          normalized_name: normalized,
          ra_digest: await signHex(RA_HMAC_SECRET, ra),
          is_admin: normalized === ADMIN_NAME,
        });
      }
      const { error } = await supabase.from("students").insert(rows);
      if (error) throw error;
      return json({ imported: rows.length, note: "Importação concluída. Os RAs não foram armazenados em texto puro." });
    }

    if (action === "login") {
      const fullName = String(body.fullName ?? "").trim();
      const normalized = normalizeName(fullName);
      const ra = normalizeRa(body.ra);
      if (!normalized || !ra || !/^\d{10,15}X?$/.test(ra)) return json({ error: "Nome completo ou RA inválido. Digite o RA sem SP." }, 400);
      const { data: student, error } = await supabase.from("students")
        .select("id, full_name, normalized_name, ra_digest, is_admin")
        .eq("normalized_name", normalized).maybeSingle();
      if (error) throw error;
      const submittedDigest = await signHex(RA_HMAC_SECRET, ra);
      if (!student || !constantTimeEqual(student.ra_digest, submittedDigest)) return json({ error: "Nome ou RA não confere. Verifique a grafia do nome completo e o RA sem SP." }, 401);
      const hasAdminCode = Boolean(ADMIN_ACCESS_CODE && constantTimeEqual(String(body.adminCode ?? ""), ADMIN_ACCESS_CODE));
      const isAdmin = Boolean(student.is_admin && hasAdminCode);
      const token = await createSession({ sid: student.id, name: student.full_name, admin: isAdmin });
      const { data: candidates, error: candidatesError } = await supabase.from("students").select("id, full_name").neq("id", student.id).order("full_name");
      if (candidatesError) throw candidatesError;
      return json({ token, studentId: student.id, fullName: student.full_name, isAdmin, candidates: candidates ?? [] });
    }

    if (action === "status") {
      const deadline = await getDeadline();
      const phase = getPhase(deadline);
      let hasVoted: boolean | null = null;
      let hasVotedGeneral: boolean | null = null;
      let hasVotedFinal: boolean | null = null;
      let isAdmin = false;
      let personalMessage: string | null = null;
      if (body.session) {
        const session = await authenticatedSession(body.session);
        isAdmin = session.admin === true;
        personalMessage = await getPersonalMessage(String(session.sid));
        const { data: studentState, error } = await supabase.from("students")
          .select("has_voted_general, has_voted_final").eq("id", session.sid).single();
        if (error) throw error;
        hasVotedGeneral = Boolean(studentState?.has_voted_general);
        hasVotedFinal = Boolean(studentState?.has_voted_final);
        hasVoted = phase === "general" ? hasVotedGeneral : phase === "final" ? hasVotedFinal : false;
      }
      const phaseDeadline = deadline && phase === "general"
        ? new Date(new Date(deadline).getTime() - 10 * DAY_MS).toISOString()
        : phase === "final" || phase === "closed" ? deadline : null;
      return json({ deadline, phaseDeadline, phase, resultsReleased: phase === "closed", hasVoted, hasVotedGeneral, hasVotedFinal, isAdmin, personalMessage, serverNow: new Date().toISOString() });
    }

    if (action === "candidates") {
      const session = await authenticatedSession(body.session);
      const { data, error } = await supabase.from("students").select("id, full_name").neq("id", session.sid).order("full_name");
      if (error) throw error;
      const deadline = await getDeadline();
      const phase = getPhase(deadline);
      const allFinalists = phase === "final" || phase === "closed" ? await getFinalistsByCategory() : {};
      // A pessoa autenticada nunca aparece como opção, mesmo se for finalista.
      const finalistsByCategory = Object.fromEntries(Object.entries(allFinalists).map(([categoryId, people]) => [categoryId, people.filter((person) => person.id !== session.sid)]));
      return json({ candidates: data ?? [], finalistsByCategory, phase });
    }

    if (action === "start_countdown") {
      await authenticatedSession(body.session, true);
      const current = await getDeadline();
      if (current) return json({ deadline: current, alreadyStarted: true });
      const deadline = new Date(Date.now() + 20 * DAY_MS).toISOString();
      const { data, error } = await supabase.from("awards_config").update({ deadline }).eq("id", 1).is("deadline", null).select("deadline").maybeSingle();
      if (error) throw error;
      if (data?.deadline) return json({ deadline: data.deadline, alreadyStarted: false });
      return json({ deadline: await getDeadline(), alreadyStarted: true });
    }

    if (action === "submit_vote") {
      const session = await authenticatedSession(body.session);
      const deadline = await getDeadline();
      const phase = getPhase(deadline);
      if (phase === "not_started") return json({ error: "A votação ainda não foi aberta pela organização." }, 409);
      if (phase === "closed") return json({ error: "O prazo de 20 dias terminou. Os resultados serão exibidos agora." }, 409);
      const rawVotes = body.votes;
      if (!rawVotes || typeof rawVotes !== "object" || Array.isArray(rawVotes)) return json({ error: "Cédula de votação inválida." }, 400);
      const entries = Object.entries(rawVotes as Record<string, unknown>);
      if (entries.length < 1) return json({ error: "Escolha ao menos uma categoria." }, 400);

      const normalizedVotes: Record<string, { first: string | null; second: string | null }> = {};
      for (const [categoryId, selection] of entries) {
        if (!categoryIds.has(categoryId)) {
          return json({ error: `A categoria "${categoryId}" ainda não é reconhecida pelo servidor. A página e o servidor estão em versões diferentes: publique a função awards-api atualizada e recarregue o site.` }, 400);
        }
        // Aceita temporariamente cédulas antigas, que armazenavam apenas uma pessoa por categoria.
        if (typeof selection === "string") {
          if (!selection) return json({ error: "Uma escolha da cédula está vazia. Atualize a página e tente novamente." }, 400);
          normalizedVotes[categoryId] = { first: selection, second: null };
          continue;
        }
        if (!selection || typeof selection !== "object" || Array.isArray(selection)) {
          return json({ error: "Uma categoria contém uma escolha inválida. Atualize a página e tente novamente." }, 400);
        }
        const ranked = selection as Record<string, unknown>;
        if ((ranked.first !== null && ranked.first !== undefined && typeof ranked.first !== "string") ||
            (ranked.second !== null && ranked.second !== undefined && typeof ranked.second !== "string")) {
          return json({ error: "Uma das opções está em formato inválido. Atualize a página e tente novamente." }, 400);
        }
        const first = typeof ranked.first === "string" && ranked.first.trim() ? ranked.first : null;
        const second = typeof ranked.second === "string" && ranked.second.trim() ? ranked.second : null;
        if (!first && !second) return json({ error: "Uma categoria enviada não tem opções selecionadas. Atualize a página e tente novamente." }, 400);
        if (second && !first) return json({ error: "Escolha a primeira opção antes da segunda. A segunda opção vale meio ponto." }, 400);
        if (first && second && first === second) return json({ error: "Escolha duas pessoas diferentes em cada categoria." }, 400);
        normalizedVotes[categoryId] = { first, second };
      }

      const candidateIds = Array.from(new Set(Object.values(normalizedVotes).flatMap((selection) => [selection.first, selection.second]).filter((id): id is string => Boolean(id))));
      // Validação no servidor: não é possível contornar a interface para votar em si mesmo.
      if (candidateIds.includes(session.sid)) return json({ error: "Você não pode votar em si mesmo(a). Escolha outra pessoa nessa categoria." }, 400);
      const { data: validCandidates, error: candidatesError } = await supabase.from("students").select("id").in("id", candidateIds);
      if (candidatesError) throw candidatesError;
      const validIds = new Set((validCandidates ?? []).map((student: any) => String(student.id)));
      if (candidateIds.some((id) => !validIds.has(id))) return json({ error: "Um ou mais indicados não são válidos." }, 400);
      if (phase === "final") {
        const finalists = await getFinalistsByCategory();
        for (const [categoryId, selection] of Object.entries(normalizedVotes)) {
          const allowed = finalists[categoryId] ?? [];
          for (const candidateId of [selection.first, selection.second].filter((id): id is string => Boolean(id))) {
            if (!allowed.some((person) => person.id === candidateId)) {
              return json({ error: "Na final, escolha entre as quatro pessoas classificadas em cada categoria. Atualize a página e confira a lista de finalistas." }, 400);
            }
          }
        }
      }
      const votes: Record<string, { first: string | null; second: string | null }> = normalizedVotes;
      const { error } = await supabase.rpc("submit_anonymous_ballot", { p_student_id: session.sid, p_votes: votes, p_phase: phase });
      if (error) {
        const msg = String(error.message ?? "");
        if (msg.includes("já enviou")) return json({ error: "Você já enviou sua cédula nesta fase." }, 409);
        if (msg.includes("prazo de votação terminou")) return json({ error: "O prazo de 20 dias terminou. Atualize a página para conferir os resultados." }, 409);
        if (msg.includes("ainda não foi aberta")) return json({ error: "A votação ainda não foi aberta pela organização." }, 409);
        if (msg.includes("fase da votação mudou")) return json({ error: "A fase mudou enquanto você votava. Atualize a página para carregar a cédula certa." }, 409);
        throw error;
      }
      return json({ success: true, phase });
    }

    if (action === "admin_stats") {
      await authenticatedSession(body.session, true);
      const deadline = await getDeadline();
      const phase = getPhase(deadline);
      const tallyPhase = phase === "final" || phase === "closed" ? "final" : "general";
      const [aggregate, phaseCounts] = await Promise.all([getAggregate(tallyPhase), getPhaseBallotCounts()]);
      return json({ ...aggregate, deadline, phase, tallyPhase, phaseCounts, resultsReleased: phase === "closed" });
    }

    if (action === "results") {
      await authenticatedSession(body.session);
      const deadline = await getDeadline();
      if (!released(deadline)) return json({ error: "Os resultados ainda estão bloqueados até o fim dos 20 dias." }, 403);
      const aggregate = await getAggregate("final");
      return json({ results: aggregate.results, totalBallots: aggregate.totalBallots });
    }

    return json({ error: "Ação desconhecida." }, 400);
  } catch (error) {
    console.error("awards-api request failed:", error instanceof Error ? error.message : "unknown error");
    return json({ error: error instanceof Error ? error.message : "Erro inesperado no servidor." }, 500);
  }
});
