# Identity and Access Control Policy Evaluation Tool

## Objective

The goal of this assignment is to build a simple Identity and Access Control Policy evaluation tool using TypeScript. The tool should be able to evaluate policies in the style of AWS IAM permission policies, permission boundaries, and resource policies.

## Starter Code

You will be provided with starter code that includes basic project structure and a few initial files. The starter code includes:

- A `Policy` interface that represents the structure of a policy
- A `PolicyEngine` class with a `loadPolicies` method and a `canAccess` method
- A test suite with some initial test cases
- An API listening on port 3000 with two endpoints: evaluate, and load-policies.

Your task is to extend the provided starter code to handle complex policy scenarios.

## Requirements

1. Modify the `PolicyEngine` class to handle the evaluation of IAM identity-based permissions policy, permission boundaries, and resource policies based on [AWS precedence and evaluation rules](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html).
2. Extend the test suite to cover complex policy scenarios, including cases with both 'Allow' and 'Deny' policies for the same resource, as well as cases involving permission boundaries and resource policies.
3. Ensure that the test suite passes and demonstrates the correct behavior of the policy evaluation tool.
4. Ensure the API can handle 100 concurrect requests - both policy mutating and policy evaluating

## Deliverables

- An updated `PolicyEngine` class that can evaluate IAM, SCP, and resource policies
- An extended test suite that covers complex policy scenarios
- A brief explanation of the evaluation and precedence rules for identity based, permission boundaries, and resource policies
- A brief plan on making this service production ready, how would this be deployed, what metrics/alerts are needed etc.

## Evaluation Criteria

- Code quality, readability, and organization
- Correct implementation of the policy evaluation rules
- Comprehensive test coverage for various policy scenarios
- Clear and concise explanation of the evaluation and precedence rules

Good luck!
