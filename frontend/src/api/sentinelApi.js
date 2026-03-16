// sentinelApi.js — Axios client for SentinelAI backend
import axios from "axios";

const BASE_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const api = axios.create({ baseURL: BASE_URL });

export const analyseInput = async ({ type, content, metadata = {} }) => {
  const { data } = await api.post("/analyse", { type, content, metadata });
  return data;
};

export const getIncidents = async (limit = 50) => {
  const { data } = await api.get(`/incidents?limit=${limit}`);
  return data;
};

export const submitFeedback = async (incidentId, verdict, note = "") => {
  const { data } = await api.post(`/feedback/${incidentId}`, {
    verdict,
    analyst_note: note,
  });
  return data;
};
