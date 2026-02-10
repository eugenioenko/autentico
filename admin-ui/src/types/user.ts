import type { components } from "./api";

export type UserCreateRequest =
  components["schemas"]["user.UserCreateRequest"];

export type UserResponse = components["schemas"]["user.UserResponse"];

// Not yet in swagger spec — defined manually to match Go UserUpdateRequest
export interface UserUpdateRequest {
  email?: string;
  role?: string;
}
