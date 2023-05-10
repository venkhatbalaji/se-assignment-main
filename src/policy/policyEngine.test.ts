import { PolicyEngine } from "./policyEngine";

describe("PolicyEngine", () => {
  let policyEngine: PolicyEngine;

  beforeEach(() => {
    policyEngine = new PolicyEngine();
  });

  describe("canAccess", () => {
    it("should allow access when an Allow policy exists for the specified resource and action", () => {
      policyEngine.loadPolicies([
        {
          id: "policy1",
          type: "PermissionsPolicy",
          principal: "*",
          effect: "Allow",
          action: ["s3:GetObject"],
          resource: ["arn:aws:s3:::example-bucket/*"],
        },
      ]);

      const result = policyEngine.canAccess(
        "user1",
        "s3:GetObject",
        "arn:aws:s3:::example-bucket/file.txt"
      );

      expect(result).toBe(true);
    });

    it("should deny access when a matching Deny policy exists for the principal, action, and resource", () => {
      const policyEngine = new PolicyEngine();
      policyEngine.loadPolicies([
        {
          id: "1",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Deny",
          action: "s3:GetObject",
          resource: "arn:aws:s3:::example-bucket/*",
        },
      ]);

      const canAccess = policyEngine.canAccess(
        "user1",
        "s3:GetObject",
        "arn:aws:s3:::example-bucket/*"
      );
      expect(canAccess).toBe(false);
    });

    it("should allow access when an explicit allow policy exists", () => {
      policyEngine.loadPolicies([
        {
          id: "policy1",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Allow",
          action: "s3:GetObject",
          resource: "arn:aws:s3:::mybucket/myobject",
        },
      ]);

      const result = policyEngine.canAccess(
        "user1",
        "s3:GetObject",
        "arn:aws:s3:::mybucket/myobject"
      );

      expect(result).toBe(true);
    });

    it("should deny access when an explicit deny policy exists", () => {
      policyEngine.loadPolicies([
        {
          id: "policy1",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Deny",
          action: "s3:GetObject",
          resource: "arn:aws:s3:::mybucket/myobject",
        },
      ]);

      const result = policyEngine.canAccess(
        "user1",
        "s3:GetObject",
        "arn:aws:s3:::mybucket/myobject"
      );

      expect(result).toBe(false);
    });

    it("should deny access when an explicit deny policy exists but there is an explicit allow policy for the same action and resource", () => {
      policyEngine.loadPolicies([
        {
          id: "policy1",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Deny",
          action: "s3:GetObject",
          resource: "arn:aws:s3:::mybucket/myobject",
        },
        {
          id: "policy2",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Allow",
          action: "s3:GetObject",
          resource: "arn:aws:s3:::mybucket/myobject",
        },
      ]);

      const result = policyEngine.canAccess(
        "user1",
        "s3:GetObject",
        "arn:aws:s3:::mybucket/myobject"
      );

      expect(result).toBe(false);
    });

    it("should deny access when an explicit deny policy exists but there is an explicit allow policy for a different action but with a wildcard for the resource", () => {
      policyEngine.loadPolicies([
        {
          id: "policy1",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Deny",
          action: "s3:GetObject",
          resource: "arn:aws:s3:::mybucket/*",
        },
        {
          id: "policy2",
          type: "PermissionsPolicy",
          principal: "user1",
          effect: "Allow",
          action: "s3:Get*",
          resource: "arn:aws:s3:::mybucket/*",
        },
      ]);

      const result = policyEngine.canAccess(
        "user1",
        "s3:GetObject",
        "arn:aws:s3:::mybucket/myobject"
      );

      expect(result).toBe(false);
    });
    it("canAccess returns correct result", () => {
      policyEngine.loadPolicies([
        {
          id: "1",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Allow",
          action: "read",
          resource: "resource-1",
        },
        {
          id: "2",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Deny",
          action: "write",
          resource: "resource-1",
        },
        {
          id: "3",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Allow",
          action: "read",
          resource: "resource-2",
        },
        {
          id: "4",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Allow",
          action: "write",
          resource: "resource-2",
        },
        {
          id: "5",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Deny",
          action: "delete",
          resource: "resource-2",
        },
        {
          id: "6",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Allow",
          action: "read",
          resource: "resource-3",
        },
        {
          id: "7",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Deny",
          action: "write",
          resource: "resource-3",
        },
        {
          id: "8",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Deny",
          action: "delete",
          resource: "resource-3",
        },
        {
          id: "9",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Allow",
          action: "r*",
          resource: "resource-4",
        },
        {
          id: "10",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Allow",
          action: "write",
          resource: "resource-4",
        },
        {
          id: "11",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Deny",
          action: "read",
          resource: "resource-1",
        },
        {
          id: "12",
          type: "PermissionsPolicy",
          principal: "user-1",
          effect: "Deny",
          action: "write",
          resource: "resource-2",
        },
      ]);
      // Deny takes precedence over Allow
      expect(policyEngine.canAccess("user-1", "read", "resource-1")).toBe(
        false
      );
      expect(policyEngine.canAccess("user-1", "write", "resource-1")).toBe(
        false
      );

      // Allow is granted when no Deny is present
      expect(policyEngine.canAccess("user-1", "read", "resource-2")).toBe(true);

      // Deny takes precedence over Allow
      expect(policyEngine.canAccess("user-1", "write", "resource-2")).toBe(
        false
      );
      expect(policyEngine.canAccess("user-1", "delete", "resource-2")).toBe(
        false
      );

      // Allow is granted when no Deny is present
      expect(policyEngine.canAccess("user-1", "read", "resource-3")).toBe(true);

      // Deny takes precedence over Allow
      expect(policyEngine.canAccess("user-1", "write", "resource-3")).toBe(
        false
      );
      expect(policyEngine.canAccess("user-1", "delete", "resource-3")).toBe(
        false
      );

      // Only Allow policies exist
      expect(policyEngine.canAccess("user-1", "reader", "resource-4")).toBe(
        false
      );
      expect(policyEngine.canAccess("user-1", "write", "resource-4")).toBe(
        true
      );
    });
  });
});
