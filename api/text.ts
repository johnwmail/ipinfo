import { handleRequest } from "../src/core";

export default {
  fetch(request: Request): Response {
    return handleRequest(request, "/text");
  },
};
