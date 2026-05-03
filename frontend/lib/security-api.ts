import { api } from "./api";

/* ── Captcha / Shield Config ── */

export type CaptchaType = "math";

export interface CaptchaConfig {
  captcha_enabled: boolean;
  captcha_type: CaptchaType;
  captcha_timeout: number;
  shield_enabled: boolean;
  shield_difficulty: number;
}

export async function getCaptchaConfig(): Promise<CaptchaConfig> {
  return api<CaptchaConfig>("/api/v1/captcha/config");
}

export async function updateCaptchaConfig(cfg: CaptchaConfig): Promise<CaptchaConfig> {
  return api<CaptchaConfig>("/api/v1/captcha/config", {
    method: "POST",
    body: JSON.stringify(cfg),
  });
}

export interface CaptchaTestResponse {
  captcha_type?: string;
  difficulty?: number;
  message?: string;
  implemented?: boolean;
  supported?: boolean;
}

export async function testCaptcha(): Promise<CaptchaTestResponse> {
  return api<CaptchaTestResponse>("/api/v1/captcha/test", { method: "POST" });
}

/* ── Chain Challenge Config ── */

export type ChainStepType = "env" | "pow" | "captcha";

export interface ChainStep {
  type: ChainStepType;
  condition: string;
}

export interface ChainConfig {
  chain_enabled: boolean;
  chain_steps: ChainStep[];
}

export async function getChainConfig(): Promise<ChainConfig> {
  return api<ChainConfig>("/api/v1/chain/config");
}

export async function updateChainConfig(cfg: ChainConfig): Promise<ChainConfig> {
  return api<ChainConfig>("/api/v1/chain/config", {
    method: "POST",
    body: JSON.stringify(cfg),
  });
}

/* ── Escalation Config ── */

export interface EscalationStep {
  threshold: number;
  action: string;
}

export interface EscalationConfig {
  escalation_enabled: boolean;
  escalation_window_secs: number;
  escalation_steps: EscalationStep[];
}

export async function getEscalationConfig(protectionId: number | string = 1): Promise<EscalationConfig> {
  return api<EscalationConfig>(`/api/v1/protection/${protectionId}/escalation`);
}

export async function updateEscalationConfig(
  protectionId: number | string,
  cfg: EscalationConfig
): Promise<EscalationConfig> {
  return api<EscalationConfig>(`/api/v1/protection/${protectionId}/escalation`, {
    method: "POST",
    body: JSON.stringify(cfg),
  });
}
