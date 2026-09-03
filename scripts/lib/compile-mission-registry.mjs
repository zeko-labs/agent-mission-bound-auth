import {
  MissionComplianceProgram
} from "../../dist-zkapp/MissionComplianceProgram.js";
import { MissionRegistry } from "../../dist-zkapp/MissionRegistry.js";

export async function compileMissionRegistry() {
  await MissionComplianceProgram.compile();
  return MissionRegistry.compile();
}
