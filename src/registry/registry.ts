import bodyParser from "body-parser";
import express from "express";
import { REGISTRY_PORT } from "../config";

export type Node = { nodeId: number; pubKey: string };

export type RegisterNodeBody = {
  nodeId: number;
  pubKey: string;
};

export type GetNodeRegistryBody = {
  nodes: Node[];
};

const nodeKeys: { [nodeId: number]: { privateKey: string; publicKey: string } } = {};


// Liste en mémoire pour stocker les nœuds enregistrés
const nodes: Node[] = [];

export async function launchRegistry() {
  const _registry = express();
  _registry.use(express.json());
  _registry.use(bodyParser.json());

  // Route de statut
  _registry.get("/status", (req, res) => {
    res.send("live");
  });

  // Route pour enregistrer les nœuds
  _registry.post("/registerNode", (req, res) => {
    const { nodeId, pubKey } = req.body as RegisterNodeBody;

    // Vérifie si le nœud est déjà enregistré pour éviter les doublons
    if (nodes.find(node => node.nodeId === nodeId)) {
      return res.status(400).send("Node already registered.");
    }

    // Enregistre le nouveau nœud
    nodes.push({ nodeId, pubKey });
    return res.status(201).send("Node registered successfully.");
  });

  const server = _registry.listen(REGISTRY_PORT, () => {
    console.log(`Registry is listening on port ${REGISTRY_PORT}`);
  });

  _registry.get("/getPrivateKey", (req, res): void => {
    const nodeId = parseInt(req.query.nodeId as string);
    const nodeKey = nodeKeys[nodeId];

    if (!nodeKey) {
      res.status(404).send("Node not found or key not generated.");
    } else {
      // Envoyer la clé privée en réponse. Attention : Ceci ne devrait être utilisé que pour les tests.
      res.json({ result: Buffer.from(nodeKey.privateKey).toString('base64') });
    }
});

  _registry.get("/getNodeRegistry", (req, res) => {
  res.json({ nodes });
  });



  return server;

}
