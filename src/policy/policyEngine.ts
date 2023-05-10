import { Policy } from "./policy";

export class PolicyEngine {
  private policies: Policy[] = [];

  public loadPolicies(policies: Policy[]): void {
    this.policies = policies;
  }

  public addPolicy(policy: Policy): void {
    this.policies.push(policy);
  }

  public canAccess(
    principal: string,
    action: string,
    resource: string
  ): boolean {
    // find all matching policies
    const matchingPolicies = this.policies.filter((policy) => {
      // check if the policy applies to the principal
      if (!this.principalMatches(policy.principal, principal)) {
        return false;
      }

      // check if the policy applies to the resource
      if (!this.resourceMatches(policy.resource, resource)) {
        return false;
      }

      // check if the policy applies to the action
      if (!this.actionMatches(policy.action, action)) {
        return false;
      }

      // check if the policy is an explicit deny
      if (policy.effect === "Deny") {
        return true;
      }

      // check if the policy is an explicit allow
      if (policy.effect === "Allow") {
        return true;
      }

      return false;
    });

    // evaluate the policies based on AWS evaluation rules
    let allow = false;
    let deny = false;

    for (const policy of matchingPolicies) {
      if (policy.effect === "Allow") {
        allow = true;
      } else if (policy.effect === "Deny") {
        deny = true;
      }
    }

    if (allow && !deny) {
      return true;
    } else if (!allow && deny) {
      return false;
    } else if (allow && deny) {
      return false;
    } else {
      // no matching policies
      return false;
    }
  }

  private resourceMatches(
    policyResource: string | string[],
    requestedResource: string
  ): boolean {
    if (policyResource === "*") {
      return true;
    }

    if (Array.isArray(policyResource)) {
      for (const resource of policyResource) {
        if (this.resourceMatches(resource, requestedResource)) {
          return true;
        }
      }

      return false;
    }

    if (Array.isArray(requestedResource)) {
      for (const resource of requestedResource) {
        if (this.resourceMatches(policyResource, resource)) {
          return true;
        }
      }

      return false;
    }

    const policyResourceParts = policyResource.split("/");
    const requestedResourceParts = requestedResource.split("/");

    if (policyResourceParts.length !== requestedResourceParts.length) {
      return false;
    }

    for (let i = 0; i < policyResourceParts.length; i++) {
      const policyResourcePart = policyResourceParts[i];
      const requestedResourcePart = requestedResourceParts[i];

      if (
        policyResourcePart !== "*" &&
        policyResourcePart !== requestedResourcePart
      ) {
        return false;
      }
    }

    return true;
  }

  private actionMatches(
    policyAction: string | string[],
    requestedAction: string
  ): boolean {
    if (policyAction === "*") {
      return true;
    }

    if (Array.isArray(policyAction)) {
      for (const action of policyAction) {
        if (this.actionMatches(action, requestedAction)) {
          return true;
        }
      }

      return false;
    }

    if (Array.isArray(requestedAction)) {
      for (const action of requestedAction) {
        if (this.actionMatches(policyAction, action)) {
          return true;
        }
      }

      return false;
    }

    const policyActionParts = policyAction.split(":");
    const requestedActionParts = requestedAction.split(":");

    if (policyActionParts.length !== requestedActionParts.length) {
      return false;
    }

    for (let i = 0; i < policyActionParts.length; i++) {
      const policyPart = policyActionParts[i];
      const requestedPart = requestedActionParts[i];

      if (policyPart !== "*" && policyPart !== requestedPart) {
        return false;
      }
    }

    return true;
  }

  private principalMatches(
    policyPrincipal: string | string[],
    requestedPrincipal: string
  ): boolean {
    if (policyPrincipal === "*") {
      return true;
    }

    if (Array.isArray(policyPrincipal)) {
      for (const principal of policyPrincipal) {
        if (this.principalMatches(principal, requestedPrincipal)) {
          return true;
        }
      }

      return false;
    }

    if (Array.isArray(requestedPrincipal)) {
      for (const principal of requestedPrincipal) {
        if (this.principalMatches(policyPrincipal, principal)) {
          return true;
        }
      }

      return false;
    }

    const policyPrincipalParts = policyPrincipal.split(":");
    const requestedPrincipalParts = requestedPrincipal.split(":");

    if (policyPrincipalParts.length !== requestedPrincipalParts.length) {
      return false;
    }

    for (let i = 0; i < policyPrincipalParts.length; i++) {
      const policyPart = policyPrincipalParts[i];
      const requestedPart = requestedPrincipalParts[i];

      if (policyPart === "*" || policyPart === requestedPart) {
        continue;
      }

      return false;
    }

    return true;
  }
}
