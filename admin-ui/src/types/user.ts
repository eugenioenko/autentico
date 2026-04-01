import type { components } from "./api";

export type UserCreateRequest =
  components["schemas"]["user.UserCreateRequest"];

export type UserResponse = components["schemas"]["user.UserResponse"];

// Not yet in swagger spec — defined manually to match Go UserUpdateRequest
export interface UserUpdateRequest {
  username?: string;
  password?: string;
  email?: string;
  role?: string;
  is_email_verified?: boolean;
  totp_verified?: boolean;
  given_name?: string;
  middle_name?: string;
  family_name?: string;
  nickname?: string;
  gender?: string;
  birthdate?: string;
  website?: string;
  profile?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  picture?: string;
  locale?: string;
  zoneinfo?: string;
  address_street?: string;
  address_locality?: string;
  address_region?: string;
  address_postal_code?: string;
  address_country?: string;
}

// Extended response fields not in swagger spec
export interface UserResponseExt {
  id: string;
  username: string;
  email: string;
  created_at: string;
  role: string;
  failed_login_attempts: number;
  locked_until: string | null;
  is_email_verified: boolean;
  totp_verified: boolean;
  given_name?: string;
  middle_name?: string;
  family_name?: string;
  nickname?: string;
  gender?: string;
  birthdate?: string;
  website?: string;
  profile?: string;
  phone_number?: string;
  phone_number_verified?: boolean;
  picture?: string;
  locale?: string;
  zoneinfo?: string;
  address_street?: string;
  address_locality?: string;
  address_region?: string;
  address_postal_code?: string;
  address_country?: string;
}
