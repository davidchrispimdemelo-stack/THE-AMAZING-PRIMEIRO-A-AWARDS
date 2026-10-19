import { createClient } from "https://esm.sh/@supabase/supabase-js@2.49.1";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
const RA_HMAC_SECRET = Deno.env.get("RA_HMAC_SECRET") ?? "";
const SESSION_SECRET = Deno.env.get("SESSION_SECRET") ?? "";
const ADMIN_ACCESS_CODE = Deno.env.get("ADMIN_ACCESS_CODE") ?? "";
const ADMIN_USERNAME = Deno.env.get("ADMIN_USERNAME") ?? "";
const ADMIN_PASSWORD = Deno.env.get("ADMIN_PASSWORD") ?? "";
const ROSTER_SETUP_KEY = Deno.env.get("ROSTER_SETUP_KEY") ?? "";
const ADMIN_NAME = "david chrispim de melo";
const DAY_MS = 24 * 60 * 60 * 1000;

const categories = [
  { id: "iconico", name: "Mais Bonito(a)" },
  { id: "mais_fofoqueiro", name: "Mais Fofoqueiro(a)" },
  { id: "mais_sem_filtro", name: "Mais Sem Filtro" },
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
  { id: "mais_estiloso", name: "Mais Estiloso(a)" },
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

function saoPauloDateString(date = new Date()): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "America/Sao_Paulo", year: "numeric", month: "2-digit", day: "2-digit",
  }).formatToParts(date);
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "00";
  return `${get("year")}-${get("month")}-${get("day")}`;
}
function acceptedAnswers(raw: unknown): string[] {
  return String(raw ?? "").split(/[|\n;]/).map((answer) => normalizeName(answer)).filter(Boolean).slice(0, 12);
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
type AwardsPhase = "not_started" | "general" | "final" | "closed";

async function getMaintenanceState(): Promise<{ enabled: boolean; message: string }> {
  const fallback = "O THE AMAZING PRIMEIRO A AWARDS está em manutenção. Voltaremos em breve.";
  const { data, error } = await supabase.from("awards_site_maintenance")
    .select("enabled, message").eq("id", 1).maybeSingle();
  if (error) {
    // Se a migração ainda não foi aplicada, não bloqueia o site; o controle ADM pedirá a migração.
    console.error("Não foi possível ler o modo manutenção:", error.message);
    return { enabled: false, message: fallback };
  }
  return { enabled: Boolean(data?.enabled), message: String(data?.message || fallback) };
}

async function getAwardsState(): Promise<{ deadline: string | null; phase: AwardsPhase }> {
  const { data, error } = await supabase
    .from("awards_config")
    .select("deadline, phase")
    .eq("id", 1)
    .single();
  if (error) throw error;

  const deadline = data?.deadline ?? null;
  const storedPhase = String(data?.phase ?? (deadline ? "general" : "not_started"));
  if (!deadline || storedPhase === "not_started") return { deadline, phase: "not_started" };
  // A fase geral continua aberta até a ADM iniciar a final, mesmo se o relógio zerar.
  if (storedPhase === "general") return { deadline, phase: "general" };
  if (storedPhase === "final" && Date.now() >= new Date(deadline).getTime()) return { deadline, phase: "closed" };
  if (storedPhase === "final") return { deadline, phase: "final" };
  return { deadline, phase: "closed" };
}

async function getDeadline(): Promise<string | null> {
  return (await getAwardsState()).deadline;
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

    if (action === "maintenance_status") {
      return json(await getMaintenanceState());
    }

    if (action === "admin_set_maintenance") {
      const admin = await authenticatedSession(body.session, true);
      const enabled = body.enabled === true;
      const rawMessage = String(body.message ?? "").trim();
      const message = rawMessage.slice(0, 240) || "O THE AMAZING PRIMEIRO A AWARDS está em manutenção. Voltaremos em breve.";
      const { error } = await supabase.from("awards_site_maintenance").upsert({
        id: 1, enabled, message, updated_at: new Date().toISOString(), updated_by: String(admin.sid),
      }, { onConflict: "id" });
      if (error) {
        if (String(error.code ?? "") === "42P01") return json({ error: "A tabela de manutenção ainda não existe. Execute a migração ARG LUXO atualizada no SQL Editor." }, 409);
        throw error;
      }
      return json({ success: true, enabled, message, updatedAt: new Date().toISOString() });
    }

    // O modo de manutenção é aplicado no servidor, não apenas escondendo elementos da página.
    // O login ADM continua liberado para que a organização possa reabrir o site.
    const maintenance = await getMaintenanceState();
    if (maintenance.enabled && action !== "admin_login") {
      if (action === "login") {
        return json({ error: maintenance.message, maintenance: true }, 503);
      }
      let isAdminSession = false;
      if (body.session) {
        try { isAdminSession = (await verifySession(body.session)).admin === true; } catch { /* sessão ausente ou expirada */ }
      }
      if (!isAdminSession) return json({ error: maintenance.message, maintenance: true }, 503);
    }

    if (action === "public_spoilers") {
      const { phase } = await getAwardsState();
      const slotMs = 15 * 60 * 1000;
      const slot = Math.floor(Date.now() / slotMs);
      const nextRefreshAt = (slot + 1) * slotMs;

      if (phase === "not_started") {
        return json({ items: [], phase, nextRefreshAt });
      }

      const tallyPhase = phase === "final" || phase === "closed" ? "final" : "general";
      const aggregate = await getAggregate(tallyPhase);
      let randomState = slot >>> 0;
      const seededRandom = () => {
        randomState = (Math.imul(randomState, 1664525) + 1013904223) >>> 0;
        return randomState / 4294967296;
      };

      const shuffled = categories.slice();
      for (let i = shuffled.length - 1; i > 0; i--) {
        const j = Math.floor(seededRandom() * (i + 1));
        [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
      }

      const items: Array<{ categoryId: string; categoryName: string; name: string; points: number; rank: number }> = [];
      for (const category of shuffled) {
        const categoryResult = aggregate.results.find((item) => item.categoryId === category.id);
        if (!categoryResult) continue;
        const eligible = categoryResult.votes.filter((person) => Number(person.count) > 0);
        if (!eligible.length) continue;
        const person = eligible[Math.floor(seededRandom() * eligible.length)];
        const rank = 1 + categoryResult.votes.filter((other) => Number(other.count) > Number(person.count)).length;
        items.push({ categoryId: category.id, categoryName: category.name, name: person.name, points: person.count, rank });
        if (items.length === 3) break;
      }

      return json({ items, phase: tallyPhase, nextRefreshAt });
    }

    if (action === "investigation_data") {
      const session = await authenticatedSession(body.session);
      const today = saoPauloDateString();
      // Uma pergunta aleatória fica fixa para cada participante durante o dia; no dia seguinte, sorteamos outra.
      let { data: personalAssignment, error: assignmentError } = await supabase.from("investigation_daily_assignments")
        .select("student_id, challenge_date, stock_id").eq("student_id", session.sid).eq("challenge_date", today).maybeSingle();
      if (assignmentError) throw assignmentError;
      let assignmentNeedsRefresh = !personalAssignment;
      if (personalAssignment) {
        const { data: assignedStock, error: assignedStockError } = await supabase.from("investigation_question_stock")
          .select("id, active").eq("id", personalAssignment.stock_id).maybeSingle();
        if (assignedStockError) throw assignedStockError;
        assignmentNeedsRefresh = !assignedStock || !assignedStock.active;
      }
      if (assignmentNeedsRefresh) {
        // A função SQL usa trava por data e renova atribuições que apontem para perguntas desativadas.
        const { error: assignError } = await supabase.rpc("assign_daily_question", {
          p_student_id: session.sid, p_challenge_date: today,
        });
        if (assignError) throw assignError;
        const { data: stableAssignment, error: stableError } = await supabase.from("investigation_daily_assignments")
          .select("student_id, challenge_date, stock_id").eq("student_id", session.sid).eq("challenge_date", today).maybeSingle();
        if (stableError) throw stableError;
        personalAssignment = stableAssignment;
      }
      let daily: any = null;
      if (personalAssignment) {
        const [{ data: stockItem, error: stockItemError }, { data: personalSolve, error: personalSolveError }] = await Promise.all([
          supabase.from("investigation_question_stock").select("id, title, prompt, active").eq("id", personalAssignment.stock_id).eq("active", true).maybeSingle(),
          supabase.from("investigation_daily_personal_solves").select("stock_id").eq("student_id", session.sid).eq("challenge_date", today).maybeSingle(),
        ]);
        if (stockItemError) throw stockItemError;
        if (personalSolveError) throw personalSolveError;
        if (stockItem) daily = { id: String(stockItem.id), challenge_date: today, title: stockItem.title, prompt: stockItem.prompt, active: true, solved: Boolean(personalSolve) };
      }
      const [{ data: puzzles, error: puzzlesError },
        { data: puzzleSolves, error: puzzleSolvesError },
        { data: tickets, error: ticketsError }, { data: submissions, error: submissionsError }, { data: easterClaim, error: easterError }] = await Promise.all([
        supabase.from("investigation_puzzles").select("id, puzzle_order, title, prompt, active")
          .eq("active", true).order("puzzle_order", { ascending: true }),
        supabase.from("investigation_puzzle_solves").select("puzzle_id").eq("student_id", session.sid),
        supabase.from("investigation_tickets").select("id, source, label, duration_hours, category_id, created_at, activated_at, expires_at")
          .eq("student_id", session.sid).order("created_at", { ascending: false }),
        supabase.from("investigation_submissions").select("id, question, status, created_at, reviewed_at")
          .eq("student_id", session.sid).order("created_at", { ascending: false }).limit(20),
        supabase.from("investigation_easter_egg_claims").select("answer").eq("student_id", session.sid).maybeSingle(),
      ]);
      for (const error of [puzzlesError, puzzleSolvesError, ticketsError, submissionsError, easterError]) if (error) throw error;
      const puzzleSolvedIds = new Set((puzzleSolves ?? []).map((row: any) => String(row.puzzle_id)));
      const dailyChallenge = daily;
      const publicPuzzles = (puzzles ?? []).map((puzzle: any) => ({
        id: String(puzzle.id), puzzle_order: puzzle.puzzle_order, title: puzzle.title,
        prompt: puzzle.prompt, active: puzzle.active, solved: puzzleSolvedIds.has(String(puzzle.id)),
        locked: (puzzles ?? []).some((prior: any) => prior.active && prior.puzzle_order < puzzle.puzzle_order && !puzzleSolvedIds.has(String(prior.id))),
      }));
      return json({ today, dailyChallenge, puzzles: publicPuzzles, tickets: tickets ?? [], submissions: submissions ?? [], easterEggClaimed: Boolean(easterClaim), easterEggAnswer: easterClaim?.answer ?? null, categories: categories.map(({ id, name }) => ({ id, name })) });
    }

    if (action === "solve_daily_challenge") {
      const session = await authenticatedSession(body.session);
      const challengeId = String(body.challengeId ?? "");
      const answer = normalizeName(body.answer);
      if (!challengeId || !answer || answer.length > 120) return json({ error: "Informe a resposta do desafio." }, 400);
      const today = saoPauloDateString();
      const [{ data: assignment, error: assignmentError }, { data: challenge, error: challengeError }, { data: solved, error: solvedError }] = await Promise.all([
        supabase.from("investigation_daily_assignments").select("stock_id").eq("student_id", session.sid).eq("challenge_date", today).maybeSingle(),
        supabase.from("investigation_question_stock").select("id, accepted_answers").eq("id", challengeId).eq("active", true).maybeSingle(),
        supabase.from("investigation_daily_personal_solves").select("stock_id").eq("student_id", session.sid).eq("challenge_date", today).maybeSingle(),
      ]);
      for (const error of [assignmentError, challengeError, solvedError]) if (error) throw error;
      if (!assignment || String(assignment.stock_id) !== challengeId || !challenge) return json({ error: "Este desafio não está atribuído à sua conta hoje." }, 404);
      if (solved) return json({ error: "Você já concluiu o desafio de hoje." }, 409);
      const answers = Array.isArray(challenge.accepted_answers) ? challenge.accepted_answers : [];
      if (!answers.some((known: unknown) => normalizeName(known) === answer)) return json({ error: "Resposta incorreta. Revise as pistas e tente novamente." }, 401);
      const { error: solveError } = await supabase.from("investigation_daily_personal_solves").insert({ student_id: session.sid, challenge_date: today, stock_id: challengeId });
      if (solveError) {
        if (String(solveError.code ?? "") === "23505") return json({ error: "Você já concluiu o desafio de hoje." }, 409);
        throw solveError;
      }
      const { data: ticket, error: ticketError } = await supabase.from("investigation_tickets").insert({ student_id: session.sid, source: "daily", source_ref: `personal:${today}:${challengeId}`, label: "Ticket VIP · Desafio do Dia", duration_hours: 6 }).select("id").single();
      if (ticketError) throw ticketError;
      return json({ success: true, ticketId: ticket.id, message: "Resposta correta! Você ganhou um Ticket VIP de 6 horas. Ative quando quiser." });
    }

    if (action === "solve_investigation_puzzle") {
      const session = await authenticatedSession(body.session);
      const puzzleId = String(body.puzzleId ?? "");
      const answer = normalizeName(body.answer);
      if (!puzzleId || !answer || answer.length > 120) return json({ error: "Informe a resposta do arquivo." }, 400);
      const { data: puzzle, error } = await supabase.from("investigation_puzzles")
        .select("id, accepted_answers, active").eq("id", puzzleId).eq("active", true).maybeSingle();
      if (error) throw error;
      if (!puzzle) return json({ error: "Este arquivo não está disponível." }, 404);
      const answers = Array.isArray(puzzle.accepted_answers) ? puzzle.accepted_answers : [];
      if (!answers.some((known: unknown) => normalizeName(known) === answer)) return json({ error: "A senha não confere. Releia o documento e tente novamente." }, 401);
      const { data: ticketId, error: awardError } = await supabase.rpc("complete_investigation_puzzle", { p_student_id: session.sid, p_puzzle_id: puzzleId });
      if (awardError) {
        const msg = String(awardError.message ?? "");
        if (msg.includes("já resolveu") || msg.includes("Resolva os arquivos anteriores")) return json({ error: msg }, 409);
        throw awardError;
      }
      return json({ success: true, ticketId, message: "Arquivo resolvido! Você ganhou um Ticket VIP de 6 horas." });
    }

    if (action === "submit_david_quiz") {
      const session = await authenticatedSession(body.session);
      const raw = body.answers && typeof body.answers === "object" ? body.answers : {};
      const prompts: Record<string, string> = {
        surname: "Complete: DAVID ______ DE MELO",
        artist: "Qual é a artista favorita do David?",
        friend: "Quem é o melhor amigo do David? O nome completo é Lucas Rafael.",
        game: "Qual é o jogo favorito do David?",
        sister: "Qual é o nome da irmã do David?",
      };
      const rows = Object.entries(prompts).map(([key, question]) => ({
        question, suggested_answer: String(raw[key] ?? "").trim().slice(0, 160), student_id: session.sid,
      })).filter((row) => row.suggested_answer.length > 0);
      if (!rows.length) return json({ error: "Responda pelo menos uma pergunta. Pode deixar as outras em branco." }, 400);
      const { data: pending, error: pendingError } = await supabase.from("investigation_submissions")
        .select("id").eq("student_id", session.sid).eq("status", "pending");
      if (pendingError) throw pendingError;
      if ((pending ?? []).length + rows.length > 20) return json({ error: "Você tem muitas respostas aguardando avaliação. Espere a ADM revisar algumas." }, 429);
      const { error } = await supabase.from("investigation_submissions").insert(rows);
      if (error) throw error;
      return json({ success: true, count: rows.length, message: `${rows.length} resposta(s) enviada(s) para a ADM revisar. Cada item será aprovado ou recusado separadamente; cada aprovação vale um Ticket VIP de 1 hora.` });
    }

    if (action === "submit_investigation_question") {
      const session = await authenticatedSession(body.session);
      const question = String(body.question ?? "").trim();
      const answer = String(body.answer ?? "").trim();
      if (question.length < 12 || question.length > 240 || answer.length < 1 || answer.length > 160) {
        return json({ error: "A pergunta precisa ter entre 12 e 240 caracteres, e a resposta até 160 caracteres." }, 400);
      }
      const normalizedQuestion = normalizeName(question);
      if (/(^|\s)ra(\s|$)/.test(normalizedQuestion) || /senha|telefone|endereço|endereco|cpf|documento pessoal/i.test(`${question} ${answer}`)) {
        return json({ error: "Envie uma curiosidade ou enigma sem dados pessoais, senhas ou informações privadas." }, 400);
      }
      const { data: pending, error: pendingError } = await supabase.from("investigation_submissions")
        .select("id").eq("student_id", session.sid).eq("status", "pending");
      if (pendingError) throw pendingError;
      if ((pending ?? []).length >= 20) return json({ error: "Você já tem 20 itens aguardando avaliação. Espere a ADM revisar." }, 429);
      const { error } = await supabase.from("investigation_submissions").insert({ student_id: session.sid, question, suggested_answer: answer });
      if (error) throw error;
      return json({ success: true, message: "Pergunta enviada para avaliação. Se for aprovada, entra na rotação diária e você ganha um Ticket VIP de 1 hora." });
    }

    if (action === "claim_investigation_easter_egg") {
      const session = await authenticatedSession(body.session);
      const answer = normalizeName(body.answer);
      if (!['sim', 'nao'].includes(answer)) return json({ error: "Escolha Sim ou Não." }, 400);
      const { data: claim, error } = await supabase.rpc("complete_investigation_easter_egg", {
        p_student_id: session.sid, p_answer: answer,
      });
      if (error) {
        if (String(error.code ?? '') === '23505') return json({ error: "Você já descobriu este easter egg nesta conta." }, 409);
        throw error;
      }
      const ticketGranted = Boolean(claim?.ticketGranted);
      const secretReveal = Boolean(claim?.secretReveal);
      return json({ success: true, ticketGranted, secretReveal,
        message: ticketGranted ? 'Easter egg encontrado! Você ganhou um Ticket VIP de 3 horas.' : 'EASTER EGG DESBLOQUEADO: a trilha sonora secreta do evento está confirmada. O mistério continua…' });
    }

    if (action === "activate_investigation_ticket") {
      const session = await authenticatedSession(body.session);
      const ticketId = String(body.ticketId ?? "");
      const categoryId = String(body.categoryId ?? "");
      if (!ticketId || !categoryIds.has(categoryId)) return json({ error: "Escolha um ticket e uma categoria válida." }, 400);
      const { data: ticket, error } = await supabase.from("investigation_tickets")
        .select("id, duration_hours, label, activated_at, expires_at")
        .eq("id", ticketId).eq("student_id", session.sid).maybeSingle();
      if (error) throw error;
      if (!ticket) return json({ error: "Este ticket não pertence à sua conta." }, 404);
      if (ticket.activated_at) return json({ error: "Este ticket já foi ativado. Cada ticket só pode ser usado uma vez." }, 409);
      const now = new Date();
      const expiresAt = new Date(now.getTime() + Number(ticket.duration_hours) * 60 * 60 * 1000).toISOString();
      const { data: updated, error: updateError } = await supabase.from("investigation_tickets")
        .update({ category_id: categoryId, activated_at: now.toISOString(), expires_at: expiresAt })
        .eq("id", ticketId).eq("student_id", session.sid).is("activated_at", null)
        .select("id, category_id, activated_at, expires_at, duration_hours").maybeSingle();
      if (updateError) throw updateError;
      if (!updated) return json({ error: "Este ticket acabou de ser utilizado. Atualize os dados." }, 409);
      const category = categories.find((item) => item.id === categoryId);
      return json({ success: true, ticket: updated, categoryName: category?.name ?? "Categoria" });
    }

    if (action === "investigation_spoiler") {
      const session = await authenticatedSession(body.session);
      const categoryId = String(body.categoryId ?? "");
      const category = categories.find((item) => item.id === categoryId);
      if (!category) return json({ error: "Categoria não encontrada." }, 404);
      const now = new Date().toISOString();
      const { data: access, error } = await supabase.from("investigation_tickets")
        .select("id, expires_at, duration_hours").eq("student_id", session.sid).eq("category_id", categoryId)
        .not("activated_at", "is", null).gt("expires_at", now).limit(1).maybeSingle();
      if (error) throw error;
      if (!access) return json({ error: "Você precisa de um ticket ativo para investigar esta categoria." }, 403);
      const { phase } = await getAwardsState();
      const tallyPhase = phase === "final" || phase === "closed" ? "final" : "general";
      const aggregate = await getAggregate(tallyPhase);
      const result = aggregate.results.find((item) => item.categoryId === categoryId);
      const ranking = (result?.votes ?? []).filter((person) => Number(person.count) > 0).map((person, index) => ({ ...person, rank: index + 1 }));
      return json({ categoryId, categoryName: category.name, phase: tallyPhase, ranking, expiresAt: access.expires_at });
    }

    if (action === "investigation_admin_data") {
      await authenticatedSession(body.session, true);
      const [{ data: students, error: studentsError }, { data: messages, error: messagesError },
        { data: daily, error: dailyError }, { data: puzzles, error: puzzlesError }, { data: submissions, error: submissionsError },
        { data: stockQuestions, error: stockQuestionsError }] = await Promise.all([
        supabase.from("students").select("id, full_name").order("full_name"),
        supabase.from("student_messages").select("student_id, message, updated_at"),
        supabase.from("investigation_daily_challenges").select("id, challenge_date, title, prompt, accepted_answers, active").order("challenge_date", { ascending: false }).limit(14),
        supabase.from("investigation_puzzles").select("id, puzzle_order, title, prompt, accepted_answers, active").order("puzzle_order", { ascending: true }),
        supabase.from("investigation_submissions").select("id, student_id, question, suggested_answer, status, created_at, students(full_name)").eq("status", "pending").order("created_at", { ascending: true }).limit(50),
        supabase.from("investigation_question_stock").select("id, title, prompt, accepted_answers, active").order("title", { ascending: true }),
      ]);
      for (const error of [studentsError, messagesError, dailyError, puzzlesError, submissionsError, stockQuestionsError]) if (error) throw error;
      return json({ students: students ?? [], messages: messages ?? [], dailyChallenges: daily ?? [], puzzles: puzzles ?? [], stockQuestions: stockQuestions ?? [], submissions: submissions ?? [], categories: categories.map(({ id, name }) => ({ id, name })) });
    }

    if (action === "investigation_admin_save_message") {
      await authenticatedSession(body.session, true);
      const studentId = String(body.studentId ?? "");
      const messageText = String(body.message ?? "").trim();
      if (!studentId || messageText.length > 1200) return json({ error: "Escolha um participante e escreva uma mensagem de até 1.200 caracteres." }, 400);
      const { data: student, error: studentError } = await supabase.from("students").select("id").eq("id", studentId).maybeSingle();
      if (studentError) throw studentError;
      if (!student) return json({ error: "Participante não encontrado." }, 404);
      if (!messageText) {
        const { error } = await supabase.from("student_messages").delete().eq("student_id", studentId);
        if (error) throw error;
        return json({ success: true, message: "Mensagem individual removida." });
      }
      const { error } = await supabase.from("student_messages").upsert({ student_id: studentId, message: messageText, updated_at: new Date().toISOString() }, { onConflict: "student_id" });
      if (error) throw error;
      return json({ success: true, message: "Mensagem individual salva." });
    }

    if (action === "admin_reset_student_vote") {
      await authenticatedSession(body.session, true);
      const fullName = String(body.fullName ?? "").trim();
      const normalized = normalizeName(fullName);
      if (normalized.length < 5) return json({ error: "Digite o nome completo da pessoa." }, 400);
      const { data: student, error: studentError } = await supabase.from("students").select("id, full_name, has_voted_general, has_voted_final, is_admin").eq("normalized_name", normalized).maybeSingle();
      if (studentError) throw studentError;
      if (!student) return json({ error: "Não encontrei uma pessoa com esse nome completo. Confira a grafia." }, 404);
      if (student.is_admin) return json({ error: "A liberação de nova cédula não pode ser usada na conta ADM." }, 400);
      const { error } = await supabase.from("students").update({ has_voted_general: false, has_voted_final: false, has_voted: false }).eq("id", student.id);
      if (error) throw error;
      return json({ success: true, fullName: student.full_name, message: `Nova cédula liberada para ${student.full_name}. IMPORTANTE: a cédula anterior é anônima e continua contabilizada; o sistema não consegue identificar qual cédula antiga pertence a essa pessoa para removê-la sem quebrar o anonimato.` });
    }

    if (action === "investigation_admin_add_stock_question") {
      await authenticatedSession(body.session, true);
      const title = String(body.title ?? "").trim();
      const prompt = String(body.prompt ?? "").trim();
      const answers = acceptedAnswers(body.answers);
      if (!title || title.length > 90 || prompt.length < 8 || prompt.length > 500 || !answers.length) {
        return json({ error: "Confira o título, a pergunta e a resposta correta. Separe respostas alternativas com |." }, 400);
      }
      const { data, error } = await supabase.from("investigation_question_stock")
        .insert({ title, prompt, accepted_answers: answers, active: true }).select("id, title, prompt, active").single();
      if (error) {
        if (String(error.code ?? "") === "23505") return json({ error: "Já existe uma pergunta com esse título no estoque. Use outro título." }, 409);
        throw error;
      }
      return json({ success: true, question: data, message: "Pergunta adicionada ao estoque. Ela poderá ser sorteada automaticamente nos próximos desafios diários." });
    }

    if (action === "investigation_admin_save_daily") {
      await authenticatedSession(body.session, true);
      const date = String(body.date ?? "");
      const title = String(body.title ?? "").trim();
      const prompt = String(body.prompt ?? "").trim();
      const answers = acceptedAnswers(body.answers);
      if (!/^\d{4}-\d{2}-\d{2}$/.test(date) || !title || title.length > 90 || prompt.length < 8 || prompt.length > 500 || !answers.length) {
        return json({ error: "Confira a data, título, pergunta e resposta correta. Separe respostas alternativas com |." }, 400);
      }
      const { data, error } = await supabase.from("investigation_daily_challenges")
        .upsert({ challenge_date: date, title, prompt, accepted_answers: answers, active: true, updated_at: new Date().toISOString() }, { onConflict: "challenge_date" })
        .select("id, challenge_date, title, prompt, active").single();
      if (error) throw error;
      return json({ success: true, challenge: data, message: "Desafio diário salvo. As respostas ficam somente no servidor." });
    }

    if (action === "investigation_admin_save_puzzle") {
      await authenticatedSession(body.session, true);
      const order = Number(body.order);
      const title = String(body.title ?? "").trim();
      const prompt = String(body.prompt ?? "").trim();
      const answers = acceptedAnswers(body.answers);
      if (!Number.isInteger(order) || order < 1 || order > 100 || !title || title.length > 100 || prompt.length < 8 || prompt.length > 500 || !answers.length) {
        return json({ error: "Confira a ordem, título, enigma e resposta. Separe respostas alternativas com |." }, 400);
      }
      const { error } = await supabase.from("investigation_puzzles").insert({ puzzle_order: order, title, prompt, accepted_answers: answers, active: true });
      if (error) {
        if (String(error.code ?? '') === '23505') return json({ error: "Já existe um arquivo com essa ordem. Escolha outro número." }, 409);
        throw error;
      }
      return json({ success: true, message: "Arquivo ARG publicado." });
    }

    if (action === "investigation_admin_review_submission") {
      await authenticatedSession(body.session, true);
      const submissionId = String(body.submissionId ?? "");
      const decision = String(body.decision ?? "");
      if (!submissionId || !["approve", "reject"].includes(decision)) return json({ error: "Decisão inválida." }, 400);
      let normalizedAnswer = "";
      if (decision === "approve") {
        const { data: submission, error: lookupError } = await supabase.from("investigation_submissions")
          .select("suggested_answer, status").eq("id", submissionId).maybeSingle();
        if (lookupError) throw lookupError;
        if (!submission || submission.status !== "pending") return json({ error: "Esta pergunta já foi avaliada ou não existe." }, 409);
        normalizedAnswer = normalizeName(submission.suggested_answer);
        if (!normalizedAnswer) return json({ error: "A resposta correta está vazia." }, 400);
      }
      const { data, error } = await supabase.rpc("review_investigation_submission", {
        p_submission_id: submissionId, p_decision: decision, p_normalized_answer: normalizedAnswer,
      });
      if (error) {
        const msg = String(error.message ?? "");
        if (msg.includes("já foi avaliada") || msg.includes("não existe")) return json({ error: msg }, 409);
        throw error;
      }
      return json(data ?? { success: true, message: decision === "approve" ? "Pergunta publicada como arquivo ARG; o autor ganhou um Ticket VIP." : "Pergunta recusada." });
    }

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

    if (action === "admin_login") {
      const username = String(body.username ?? "").trim();
      const password = String(body.password ?? "");

      if (!ADMIN_USERNAME || !ADMIN_PASSWORD) {
        return json({ error: "O login administrativo não está configurado." }, 500);
      }
      if (!username || !password || password.length > 512 ||
          !constantTimeEqual(username, ADMIN_USERNAME) ||
          !constantTimeEqual(password, ADMIN_PASSWORD)) {
        return json({ error: "Usuário ou senha incorretos." }, 401);
      }

      const { data: adminStudent, error: adminError } = await supabase
        .from("students")
        .select("id, full_name")
        .eq("normalized_name", ADMIN_NAME)
        .eq("is_admin", true)
        .maybeSingle();
      if (adminError) throw adminError;
      if (!adminStudent) {
        return json({ error: "O registro ADM não foi encontrado na lista de participantes." }, 409);
      }

      const token = await createSession({ sid: adminStudent.id, name: adminStudent.full_name, admin: true });
      const { data: candidates, error: candidatesError } = await supabase
        .from("students")
        .select("id, full_name")
        .neq("id", adminStudent.id)
        .order("full_name");
      if (candidatesError) throw candidatesError;
      return json({ token, studentId: adminStudent.id, fullName: adminStudent.full_name, isAdmin: true, candidates: candidates ?? [] });
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
      const isAdmin = false;
      const token = await createSession({ sid: student.id, name: student.full_name, admin: isAdmin });
      const { data: candidates, error: candidatesError } = await supabase.from("students").select("id, full_name").neq("id", student.id).order("full_name");
      if (candidatesError) throw candidatesError;
      return json({ token, studentId: student.id, fullName: student.full_name, isAdmin, candidates: candidates ?? [] });
    }

    if (action === "status") {
      const { deadline, phase } = await getAwardsState();
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
      const phaseDeadline = phase === "general" || phase === "final" || phase === "closed" ? deadline : null;
      return json({ deadline, phaseDeadline, phase, resultsReleased: phase === "closed", hasVoted, hasVotedGeneral, hasVotedFinal, isAdmin, personalMessage, serverNow: new Date().toISOString() });
    }

    if (action === "candidates") {
      const session = await authenticatedSession(body.session);
      const { data, error } = await supabase.from("students").select("id, full_name").neq("id", session.sid).order("full_name");
      if (error) throw error;
      const { deadline, phase } = await getAwardsState();
      const allFinalists = phase === "final" || phase === "closed" ? await getFinalistsByCategory() : {};
      // A pessoa autenticada nunca aparece como opção, mesmo se for finalista.
      const finalistsByCategory = Object.fromEntries(Object.entries(allFinalists).map(([categoryId, people]) => [categoryId, people.filter((person) => person.id !== session.sid)]));
      return json({ candidates: data ?? [], finalistsByCategory, phase });
    }

    if (action === "start_countdown") {
      await authenticatedSession(body.session, true);
      const current = await getAwardsState();
      if (current.phase !== "not_started") return json({ deadline: current.deadline, alreadyStarted: true });
      // Prazo fixo: 29/10/2026 às 23:59:59 no horário de Brasília.
      const deadline = "2026-10-30T02:59:59.000Z";
      const { data, error } = await supabase.from("awards_config")
        .update({ deadline, phase: "general" })
        .eq("id", 1).is("deadline", null).eq("phase", "not_started")
        .select("deadline, phase").maybeSingle();
      if (error) throw error;
      if (data?.deadline) return json({ deadline: data.deadline, phase: data.phase, alreadyStarted: false });
      const latest = await getAwardsState();
      return json({ deadline: latest.deadline, phase: latest.phase, alreadyStarted: true });
    }

    if (action === "start_final") {
      await authenticatedSession(body.session, true);
      const current = await getAwardsState();
      if (current.phase !== "general" || !current.deadline) {
        return json({ error: "A segunda fase só pode começar enquanto a primeira estiver aberta." }, 409);
      }

      const { data: ballots, error: ballotsError } = await supabase
        .from("ballots").select("ballot_id").eq("phase", "general");
      if (ballotsError) throw ballotsError;
      const total = ballots?.length ?? 0;
      if (total < 20) {
        return json({ error: `Ainda são necessárias 20 cédulas da primeira fase. Recebidas: ${total}/20.` }, 409);
      }

      // Prazo fixo: 08/11/2026 às 23:59:59 no horário de Brasília.
      const deadline = "2026-11-09T02:59:59.000Z";
      const { data, error } = await supabase.from("awards_config")
        .update({ deadline, phase: "final" })
        .eq("id", 1).eq("phase", "general").eq("deadline", current.deadline)
        .select("deadline, phase").maybeSingle();
      if (error) throw error;
      if (!data) return json({ error: "A fase mudou enquanto você iniciava a final. Atualize a página." }, 409);
      return json({ success: true, deadline: data.deadline, phase: data.phase, totalGeneralBallots: total });
    }

    if (action === "submit_vote") {
      const session = await authenticatedSession(body.session);
      const { deadline, phase } = await getAwardsState();
      if (phase === "not_started") return json({ error: "A votação ainda não foi aberta pela organização." }, 409);
      if (phase === "closed") return json({ error: "O prazo da fase atual terminou. Atualize a página para conferir os resultados." }, 409);
      if (phase === "general" && deadline && Date.now() >= new Date(deadline).getTime()) return json({ error: "A Fase 1 terminou em 29/10. Aguarde a ADM abrir a Fase 2." }, 409);
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
        if (msg.includes("prazo de votação terminou")) return json({ error: "O prazo da fase atual terminou. Atualize a página para conferir os resultados." }, 409);
        if (msg.includes("ainda não foi aberta")) return json({ error: "A votação ainda não foi aberta pela organização." }, 409);
        if (msg.includes("fase da votação mudou")) return json({ error: "A fase mudou enquanto você votava. Atualize a página para carregar a cédula certa." }, 409);
        throw error;
      }
      return json({ success: true, phase });
    }

    if (action === "admin_stats") {
      await authenticatedSession(body.session, true);
      const { deadline, phase } = await getAwardsState();
      const tallyPhase = phase === "final" || phase === "closed" ? "final" : "general";
      const [aggregate, phaseCounts] = await Promise.all([getAggregate(tallyPhase), getPhaseBallotCounts()]);
      return json({ ...aggregate, deadline, phase, tallyPhase, phaseCounts, resultsReleased: phase === "closed" });
    }

    if (action === "results") {
      await authenticatedSession(body.session);
      const { phase } = await getAwardsState();
      if (phase !== "closed") return json({ error: "Os resultados oficiais ficam disponíveis ao terminar o prazo da final." }, 403);
      const aggregate = await getAggregate("final");
      return json({ results: aggregate.results, totalBallots: aggregate.totalBallots });
    }

    return json({ error: "Ação desconhecida." }, 400);
  } catch (error) {
    console.error("awards-api request failed:", error instanceof Error ? error.message : "unknown error");
    return json({ error: error instanceof Error ? error.message : "Erro inesperado no servidor." }, 500);
  }
});
