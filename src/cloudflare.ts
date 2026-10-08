import { handleRequest } from "./core";

export default {
  fetch(request: Request): Response {
    return handleRequest(request, new URL(request.url).pathname);
  },
};
