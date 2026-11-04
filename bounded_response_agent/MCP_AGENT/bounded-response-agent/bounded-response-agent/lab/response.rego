package bra.response

import rego.v1

default allow := false

allow if {
    input.profile in {"shipboard", "enterprise"}
    input.simulation_allowed
    authorized_phase
    target_allowed
    mission_ready
}

role_levels := {"soc_operator": 1, "ot_supervisor": 2, "ship_cio": 3}

authorized_phase if {
    input.phase == "proposal"
}

authorized_phase if {
    input.phase in {"approval", "execution"}
    role_levels[input.operator_role] >= role_levels[input.required_role]
}


target_allowed if {
    input.target in input.scope[input.action]
}

mission_ready if {
    input.action != "isolate_endpoint"
    input.cooling_healthy
}

mission_ready if {
    input.action == "isolate_endpoint"
    input.cooling_healthy
    input.cooling_source == input.expected_backup
}

decision := {"allow": allow, "revision": "shipboard-lab-v2"}
