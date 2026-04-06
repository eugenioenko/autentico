export interface Group {
  id: string;
  name: string;
  description: string;
  created_at: string;
  updated_at: string;
}

export interface GroupCreateRequest {
  name: string;
  description?: string;
}

export interface GroupUpdateRequest {
  name?: string;
  description?: string;
}

export interface GroupMember {
  user_id: string;
  username: string;
  email: string;
  created_at: string;
}
