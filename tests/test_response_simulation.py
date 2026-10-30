from app.incidents.response import simulate


def test_simulate_rejects_unrecognized_action():
    outcome = simulate("delete_the_database", "victim3", "203.0.113.50", approved=True)
    assert "not a recognized response action" in outcome


def test_simulate_all_supported_actions_produce_simulated_output():
    for action in ["revoke_sessions", "disable_account", "block_ip", "request_password_reset"]:
        outcome = simulate(action, "victim3", "203.0.113.50", approved=True)
        assert outcome.startswith("[SIMULATED]")
