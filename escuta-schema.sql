-- =====================================================================
-- Escuta: aplicativo de monitoramento de saúde mental (FMU, ADS, ODS 3)
-- Esquema de banco de dados PostgreSQL 15+
--
-- Ideia central: o consentimento do usuário é aplicado pelo PRÓPRIO BANCO,
-- com Row Level Security (RLS). Mesmo que a API tenha um erro, um
-- profissional só consegue ler registros que o usuário autorizou.
--
-- A aplicação define, a cada requisição autenticada:
--   SET app.usuario_id = '<uuid>';  ou  SET app.profissional_id = '<uuid>';
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TYPE humor_tipo        AS ENUM ('bem', 'mal', 'ajuda');
CREATE TYPE rede_tipo         AS ENUM ('publica', 'social', 'privada');
CREATE TYPE conselho_tipo     AS ENUM ('CRP', 'CRM');
CREATE TYPE verificacao_tipo  AS ENUM ('pendente', 'verificado', 'recusado');
CREATE TYPE modalidade_tipo   AS ENUM ('chat', 'ligacao', 'video');

-- ---------------------------------------------------------------------
-- Pessoas
-- ---------------------------------------------------------------------
CREATE TABLE usuario (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nome             text        NOT NULL,
  email            text        NOT NULL UNIQUE,
  senha_hash       text        NOT NULL,            -- bcrypt/argon2, nunca a senha
  cidade           text,
  lembrete_hora    time        DEFAULT '20:00',
  aceite_termos_em timestamptz NOT NULL,
  criado_em        timestamptz NOT NULL DEFAULT now(),
  excluido_em      timestamptz                       -- exclusão a pedido (LGPD, art. 18, VI)
);

CREATE TABLE profissional (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  nome             text             NOT NULL,
  email            text             NOT NULL UNIQUE,
  senha_hash       text             NOT NULL,
  profissao        text             NOT NULL,
  conselho         conselho_tipo    NOT NULL,
  conselho_uf      char(2)          NOT NULL,
  conselho_numero  text             NOT NULL,
  verificacao      verificacao_tipo NOT NULL DEFAULT 'pendente',
  rede             rede_tipo        NOT NULL,
  valor_sessao     numeric(8,2)     CHECK (valor_sessao >= 0),
  cidade           text,
  bairro           text,
  online           boolean          NOT NULL DEFAULT true,
  presencial       boolean          NOT NULL DEFAULT false,
  plantao          boolean          NOT NULL DEFAULT false,   -- aceita pedidos de ajuda imediatos
  abordagem        text,
  criado_em        timestamptz      NOT NULL DEFAULT now(),
  UNIQUE (conselho, conselho_uf, conselho_numero)
);

-- Disponibilidade semanal (0 = domingo ... 6 = sábado)
CREATE TABLE disponibilidade (
  profissional_id  uuid     NOT NULL REFERENCES profissional(id) ON DELETE CASCADE,
  dia_semana       smallint NOT NULL CHECK (dia_semana BETWEEN 0 AND 6),
  hora             time     NOT NULL,
  PRIMARY KEY (profissional_id, dia_semana, hora)
);

-- ---------------------------------------------------------------------
-- Registros de humor e rotina (dados pessoais sensíveis)
-- ---------------------------------------------------------------------
CREATE TABLE registro (
  id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id     uuid        NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
  criado_em      timestamptz NOT NULL DEFAULT now(),
  humor          humor_tipo  NOT NULL,
  sono_horas     numeric(3,1) CHECK (sono_horas BETWEEN 0 AND 24),
  sono_qualidade smallint     CHECK (sono_qualidade BETWEEN 1 AND 5),
  atividade_min  smallint     CHECK (atividade_min >= 0),
  trabalho_horas numeric(3,1) CHECK (trabalho_horas BETWEEN 0 AND 24),
  contato_social boolean,
  alimentacao_ok boolean,
  sentimentos    text[]       NOT NULL DEFAULT '{}',
  nota_cifrada   bytea        -- anotação livre cifrada na aplicação (RNF02)
);
CREATE INDEX registro_usuario_data ON registro (usuario_id, criado_em DESC);

-- ---------------------------------------------------------------------
-- Consentimento: específico, destacado e revogável (LGPD, art. 11)
-- ---------------------------------------------------------------------
CREATE TABLE consentimento (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id       uuid        NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
  profissional_id  uuid        NOT NULL REFERENCES profissional(id) ON DELETE CASCADE,
  ver_humor        boolean     NOT NULL DEFAULT true,
  ver_rotina       boolean     NOT NULL DEFAULT false,
  ver_notas        boolean     NOT NULL DEFAULT false,
  periodo_dias     smallint,                          -- NULL = todo o histórico
  avisar_em_crise  boolean     NOT NULL DEFAULT false, -- profissional de referência
  concedido_em     timestamptz NOT NULL DEFAULT now(),
  expira_em        timestamptz,
  revogado_em      timestamptz
);
-- Só um consentimento ativo por par usuário-profissional
CREATE UNIQUE INDEX consentimento_ativo ON consentimento (usuario_id, profissional_id) WHERE revogado_em IS NULL;

-- ---------------------------------------------------------------------
-- Atendimento
-- ---------------------------------------------------------------------
CREATE TABLE agendamento (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id       uuid            NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
  profissional_id  uuid            NOT NULL REFERENCES profissional(id),
  inicio           timestamptz     NOT NULL,
  modalidade       modalidade_tipo NOT NULL,
  cancelado_em     timestamptz,
  criado_em        timestamptz     NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX agenda_sem_conflito ON agendamento (profissional_id, inicio) WHERE cancelado_em IS NULL;

CREATE TABLE mensagem (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id       uuid        NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
  profissional_id  uuid        NOT NULL REFERENCES profissional(id),
  autor            char(1)     NOT NULL CHECK (autor IN ('u', 'p', 's')),   -- s = sistema
  texto_cifrado    bytea       NOT NULL,
  enviada_em       timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE alerta_crise (
  id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  usuario_id       uuid        NOT NULL REFERENCES usuario(id) ON DELETE CASCADE,
  profissional_id  uuid        NOT NULL REFERENCES profissional(id),
  criado_em        timestamptz NOT NULL DEFAULT now(),
  atendido_em      timestamptz
);

-- ---------------------------------------------------------------------
-- Auditoria de acessos (RNF03): só recebe INSERT, nunca UPDATE/DELETE
-- ---------------------------------------------------------------------
CREATE TABLE auditoria (
  id          bigserial PRIMARY KEY,
  em          timestamptz NOT NULL DEFAULT now(),
  ator_tipo   text        NOT NULL CHECK (ator_tipo IN ('usuario', 'profissional', 'sistema')),
  ator_id     uuid,
  acao        text        NOT NULL,
  usuario_alvo uuid
);
REVOKE UPDATE, DELETE ON auditoria FROM PUBLIC;

-- ---------------------------------------------------------------------
-- Funções auxiliares para as políticas
-- ---------------------------------------------------------------------
CREATE FUNCTION app_usuario() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.usuario_id', true), '')::uuid $$;

CREATE FUNCTION app_profissional() RETURNS uuid LANGUAGE sql STABLE AS
$$ SELECT nullif(current_setting('app.profissional_id', true), '')::uuid $$;

-- Consentimento ativo e não expirado entre o profissional logado e o usuário
CREATE FUNCTION consentimento_vigente(p_usuario uuid)
RETURNS consentimento LANGUAGE sql STABLE AS $$
  SELECT c.* FROM consentimento c
   WHERE c.usuario_id = p_usuario
     AND c.profissional_id = app_profissional()
     AND c.revogado_em IS NULL
     AND (c.expira_em IS NULL OR c.expira_em > now())
   LIMIT 1
$$;

-- ---------------------------------------------------------------------
-- Row Level Security
-- ---------------------------------------------------------------------
ALTER TABLE registro      ENABLE ROW LEVEL SECURITY;
ALTER TABLE consentimento ENABLE ROW LEVEL SECURITY;
ALTER TABLE mensagem      ENABLE ROW LEVEL SECURITY;
ALTER TABLE agendamento   ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerta_crise  ENABLE ROW LEVEL SECURITY;

-- O usuário vê e altera apenas os próprios registros
CREATE POLICY registro_dono ON registro
  USING (usuario_id = app_usuario())
  WITH CHECK (usuario_id = app_usuario());

-- O profissional lê apenas o que foi autorizado, dentro do período autorizado
CREATE POLICY registro_profissional ON registro FOR SELECT
  USING (
    (consentimento_vigente(usuario_id)).id IS NOT NULL
    AND (consentimento_vigente(usuario_id)).ver_humor
    AND ( (consentimento_vigente(usuario_id)).periodo_dias IS NULL
          OR criado_em >= now() - make_interval(days => (consentimento_vigente(usuario_id)).periodo_dias) )
  );

-- Rotina e anotações ficam ocultas por padrão: a API usa esta visão para profissionais
CREATE VIEW registro_para_profissional WITH (security_barrier) AS
SELECT r.id, r.usuario_id, r.criado_em, r.humor,
       CASE WHEN (consentimento_vigente(r.usuario_id)).ver_rotina THEN r.sono_horas     END AS sono_horas,
       CASE WHEN (consentimento_vigente(r.usuario_id)).ver_rotina THEN r.sono_qualidade END AS sono_qualidade,
       CASE WHEN (consentimento_vigente(r.usuario_id)).ver_rotina THEN r.atividade_min  END AS atividade_min,
       CASE WHEN (consentimento_vigente(r.usuario_id)).ver_rotina THEN r.trabalho_horas END AS trabalho_horas,
       CASE WHEN (consentimento_vigente(r.usuario_id)).ver_rotina THEN r.sentimentos    END AS sentimentos,
       CASE WHEN (consentimento_vigente(r.usuario_id)).ver_notas  THEN r.nota_cifrada   END AS nota_cifrada
  FROM registro r;

CREATE POLICY consentimento_dono ON consentimento
  USING (usuario_id = app_usuario())
  WITH CHECK (usuario_id = app_usuario());
CREATE POLICY consentimento_leitura_prof ON consentimento FOR SELECT
  USING (profissional_id = app_profissional());

CREATE POLICY mensagem_participantes ON mensagem
  USING (usuario_id = app_usuario() OR profissional_id = app_profissional());

CREATE POLICY agendamento_participantes ON agendamento
  USING (usuario_id = app_usuario() OR profissional_id = app_profissional());

CREATE POLICY alerta_participantes ON alerta_crise
  USING (usuario_id = app_usuario() OR profissional_id = app_profissional());

-- ---------------------------------------------------------------------
-- Gatilho: todo pedido de ajuda avisa o profissional de referência,
-- somente se o usuário autorizou o aviso em crise
-- ---------------------------------------------------------------------
CREATE FUNCTION avisar_referencia() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.humor = 'ajuda' THEN
    INSERT INTO alerta_crise (usuario_id, profissional_id)
    SELECT NEW.usuario_id, c.profissional_id
      FROM consentimento c
     WHERE c.usuario_id = NEW.usuario_id
       AND c.avisar_em_crise
       AND c.revogado_em IS NULL
       AND (c.expira_em IS NULL OR c.expira_em > now());
    INSERT INTO auditoria (ator_tipo, ator_id, acao, usuario_alvo)
    VALUES ('sistema', NULL, 'alerta de crise enviado ao profissional de referência', NEW.usuario_id);
  END IF;
  RETURN NEW;
END $$;

CREATE TRIGGER registro_alerta AFTER INSERT ON registro
  FOR EACH ROW EXECUTE FUNCTION avisar_referencia();