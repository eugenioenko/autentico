import type { components } from "./api";

export type UserCreateRequest =
  components["schemas"]["user.UserCreateRequest"];

export type UserResponse = components["schemas"]["user.UserResponse"];

// Not yet in swagger spec — defined manually to match Go UserUpdateRequest
export interface UserUpdateRequest {
  email?: string;
  role?: string;
}

// Extended response fields not in swagger spec
export interface UserResponseExt {
  id?: string;
  username?: string;
  email?: string;
  created_at?: string;
  role?: string;
  failed_login_attempts?: number;
  locked_until?: string | null;
}
