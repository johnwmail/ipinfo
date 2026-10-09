import { handleRequest } from "../src/core.js";

export default {
  fetch(request: Request): Response {
    return handleRequest(request, "/ip");
  },
};
