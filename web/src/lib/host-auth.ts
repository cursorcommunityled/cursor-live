import { createHash, timingSafeEqual } from "crypto";
import type { PublicRoomState, RoomState } from "./slides";

export const MIN_HOST_KEY_LENGTH = 8;

export function hashHostKey(key: string) {
  return createHash("sha256").update(key.trim()).digest("hex");
}

export function hostKeysMatch(storedHash: string, candidateKey: string) {
  const candidate = hashHostKey(candidateKey);
  const a = Buffer.from(storedHash);
  const b = Buffer.from(candidate);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function isAdminHostKey(hostKey?: string) {
  const admin = process.env.HOST_KEY?.trim();
  const candidate = hostKey?.trim() ?? "";
  if (!admin || !candidate) return false;
  const a = Buffer.from(admin);
  const b = Buffer.from(candidate);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export function toPublicRoom(room: RoomState): PublicRoomState {
  const { hostKeyHash, ...rest } = room;
  return {
    ...rest,
    hasHostKey: Boolean(hostKeyHash),
  };
}

export function validateHostKeyInput(hostKey?: string) {
  const value = hostKey?.trim() ?? "";
  if (value.length < MIN_HOST_KEY_LENGTH) {
    return `La clave debe tener al menos ${MIN_HOST_KEY_LENGTH} caracteres.`;
  }
  return null;
}
