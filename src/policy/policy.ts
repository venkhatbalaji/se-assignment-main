export interface Policy {
  id: string;
  type: "PermissionsPolicy" | "PermissionsBoundary" | "ResourcePolicy";
  principal: string | string[];
  effect: "Allow" | "Deny";
  action: string | string[];
  resource: string | string[];
}
