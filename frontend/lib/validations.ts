import { z } from "zod";

export const scanUrlSchema = z.object({
  url: z.string().url({ message: "Please enter a valid URL (e.g. https://example.com)" }),
});
