const trueValues = new Set(["1", "t", "T", "TRUE", "true", "True"]);

/** Matches the server's strconv.ParseBool so the UI reflects the effective setting. */
export function isSettingOn(value: unknown): boolean {
  return value === true || (typeof value === "string" && trueValues.has(value));
}
