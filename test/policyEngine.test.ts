import {describe, expect, test} from '@jest/globals';
import { PolicyEngine } from '../src/policy/policyEngine';
import { Policy } from '../src/policy/policy';

describe('PolicyEngine', () => {
  test('canAccess returns false when no policies are loaded', () => {
    const policyEngine = new PolicyEngine();
    expect(policyEngine.canAccess('user-1', 'read', 'resource-1')).toBe(false);
  });
});

describe('PolicyEngine', () => {
    test('canAccess returns correct result', () => {
      const policyEngine = new PolicyEngine();
  
      const policies = [
        { id: '1', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Allow', action: 'read', resource: 'resource-1' },
        { id: '2', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Deny', action: 'write', resource: 'resource-1' },
        { id: '3', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Allow', action: 'read', resource: 'resource-2' },
        { id: '4', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Allow', action: 'write', resource: 'resource-2' },
        { id: '5', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Deny', action: 'delete', resource: 'resource-2' },
        { id: '6', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Allow', action: 'read', resource: 'resource-3' },
        { id: '7', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Deny', action: 'write', resource: 'resource-3' },
        { id: '8', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Deny', action: 'delete', resource: 'resource-3' },
        { id: '9', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Allow', action: 'r*', resource: 'resource-4' },
        { id: '10', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Allow', action: 'write', resource: 'resource-4' },
        { id: '11', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Deny', action: 'read', resource: 'resource-1' },
        { id: '12', type: 'PermissionsPolicy', principal: 'user-1', effect: 'Deny', action: 'write', resource: 'resource-2' }
      ] as Policy[];
  
      policyEngine.loadPolicies(policies);
  
      // Deny takes precedence over Allow
      expect(policyEngine.canAccess('user-1', 'read', 'resource-1')).toBe(false);
      expect(policyEngine.canAccess('user-1', 'write', 'resource-1')).toBe(false);
  
      // Allow is granted when no Deny is present
      expect(policyEngine.canAccess('user-1', 'read', 'resource-2')).toBe(true);
  
      // Deny takes precedence over Allow
      expect(policyEngine.canAccess('user-1', 'write', 'resource-2')).toBe(false);
      expect(policyEngine.canAccess('user-1', 'delete', 'resource-2')).toBe(false);
  
      // Allow is granted when no Deny is present
      expect(policyEngine.canAccess('user-1', 'read', 'resource-3')).toBe(true);
  
      // Deny takes precedence over Allow
      expect(policyEngine.canAccess('user-1', 'write', 'resource-3')).toBe(false);
      expect(policyEngine.canAccess('user-1', 'delete', 'resource-3')).toBe(false);
  
      // Only Allow policies exist
      expect(policyEngine.canAccess('user-1', 'reader', 'resource-4')).toBe(true);
      expect(policyEngine.canAccess('user-1', 'write', 'resource-4')).toBe(true);
    });
  
    // TODO: Add more tests for various policy scenarios
  });