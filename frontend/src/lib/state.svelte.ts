import { getMe, type GetMeResult } from "./api";

let me = $state<GetMeResult | null>(null);

export async function updateMeFromAPI() {
  me = await getMe();
  return me;
}

export function getLocalMe() {
  return me;
}
