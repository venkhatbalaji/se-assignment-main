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
  });
});
