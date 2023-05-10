import express from "express";
import { PolicyEngine } from "../policy/policyEngine";

const app = express();
const port = 3000;

const policyEngine = new PolicyEngine();

app.use(express.json());

app.post("/load-policies", (req, res) => {
  const policies = req.body;
  if (!policies) {
    return res.status(400).send("Missing required parameters");
  }
  policyEngine.loadPolicies(policies);
  res.status(200).send("Policies loaded successfully");
});

app.post("/evaluate", (req, res) => {
  const { principal, action, resource } = req.body;
  if (!principal || !action || !resource) {
    return res.status(400).send("Missing required parameters");
  }
  const canAccess = policyEngine.canAccess(principal, action, resource);
  if (canAccess) {
    res.status(200).send("Access granted");
  } else {
    res.status(403).send("Access denied");
  }
});

app.listen(port, () => {
  console.log(`Policy evaluator listening at http://localhost:${port}`);
});
