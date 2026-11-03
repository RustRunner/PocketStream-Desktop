// Uses the existing instance providers and barriers. No native policy is run.
mod policy_retry_tests {
    use super::*;
    use std::time::Duration;

    fn refused() -> PolicyResult {
        PolicyResult {
            admitted: false,
            outcome: FirewallOutcome::Unavailable {
                reason: "admission timeout".into(),
            },
        }
    }
    fn failure(stage: &str, uncertain: bool) -> PolicyResult {
        PolicyResult::accepted(FirewallOutcome::Failed {
            stage: stage.into(),
            reason: "injected policy failure".into(),
            uncertain,
        })
    }
    fn applied() -> PolicyResult {
        PolicyResult::accepted(FirewallOutcome::Applied {
            rule_name: "owned-test-rule".into(),
            action: firewall::RuleAction::Updated,
            verified_shape: true,
            observed_block_rules: vec![],
        })
    }
    fn delay(retry: &PolicyRetry) -> Option<Duration> {
        retry
            .due
            .map(|due| due.saturating_duration_since(tokio::time::Instant::now()))
    }
    async fn due(manager: &StreamManager) -> (u64, u64) {
        let mut state = manager.relay.state.lock().await;
        let epoch = state.restream_intent_epoch.unwrap();
        let retry = state.policy_retry.as_mut().unwrap();
        retry.due = Some(tokio::time::Instant::now());
        (retry.generation, epoch)
    }
    async fn listening(
        protocol: RestreamProtocol,
        explicit_bind: bool,
    ) -> (StreamManager, AppSettings, Arc<Policy>) {
        let bindings = Bindings::new(
            &[],
            (0..12)
                .map(|_| Read::ready(observation(explicit_bind, 1)))
                .collect(),
        );
        let policy = Arc::new(Policy::default());
        policy.ensure_results.lock().unwrap().push_back(refused());
        let (manager, settings) = fixture(protocol, explicit_bind, bindings, policy.clone());
        let info = start(&manager.relay, &settings).await.unwrap();
        assert_eq!(info.firewall, refused().outcome);
        (manager, settings, policy)
    }

    #[tokio::test(start_paused = true)]
    async fn classification_uses_current_stages_admission_and_actual_uncertainty() {
        for stage in [
            "shape",
            "prepare",
            "blocks",
            "enable",
            "readback",
            "native_timeout",
            "native_canceled",
            "native_containment",
            "native_output",
            "native_report",
            "disable",
            "input",
            "access",
            "inventory",
            "ownership",
            "trusted_modules",
            "native_setup",
            "native_task",
            "unknown",
        ] {
            for retiring in [false, true] {
                for uncertain in [false, true] {
                    let mut retry = PolicyRetry::new(7);
                    retry.observe(&failure(stage, uncertain), retiring, false);
                    let expected = [
                        "shape",
                        "prepare",
                        "blocks",
                        "enable",
                        "readback",
                        "native_timeout",
                        "native_canceled",
                        "native_containment",
                        "native_output",
                        "native_report",
                    ]
                    .contains(&stage)
                        || (stage == "disable" && retiring);
                    assert_eq!(
                        delay(&retry),
                        (!uncertain && expected).then_some(Duration::from_secs(60)),
                        "{stage}, retiring={retiring}, uncertain={uncertain}"
                    );
                    assert_eq!(retry.transient_failures, 0);
                }
            }
        }
        let mut retry = PolicyRetry::new(7);
        retry.observe(&refused(), false, true);
        let due = retry.due;
        retry.observe(
            &PolicyResult {
                admitted: false,
                outcome: FirewallOutcome::Inactive,
            },
            false,
            true,
        );
        assert_eq!(retry.due, due);
        assert_eq!(retry.admission_attempt, 1);
        retry.observe(
            &PolicyResult::accepted(FirewallOutcome::Inactive),
            false,
            true,
        );
        assert_eq!(
            retry.due, None,
            "unexpected Ensure Inactive requires explicit refresh"
        );
        retry.observe(&PolicyResult::accepted(refused().outcome), false, true);
        assert_eq!(retry.due, None, "admitted Unavailable is terminal");
        let mut unadmitted_failure = failure("readback", false);
        unadmitted_failure.admitted = false;
        retry.observe(&unadmitted_failure, false, true);
        assert_eq!(retry.due, None);
        retry.due = due;
        retry.observe(&applied(), true, true);
        assert_eq!(retry.due, None, "Applied is not successful retirement");
    }

    #[tokio::test(start_paused = true)]
    async fn admission_backoff_and_failure_budget_survive_success_and_rebuild() {
        let mut retry = PolicyRetry::new(7);
        for seconds in [2, 5, 15, 30, 60, 60, 60] {
            tokio::time::advance(Duration::from_secs(19)).await;
            retry.observe(&refused(), false, true);
            assert_eq!(
                delay(&retry),
                Some(Duration::from_secs(seconds)),
                "delay starts at completion"
            );
            assert_eq!(retry.transient_failures, 0);
        }
        retry.admission_attempt = u32::MAX;
        retry.observe(&refused(), false, true);
        assert_eq!(retry.admission_attempt, u32::MAX);
        assert_eq!(delay(&retry), Some(Duration::from_secs(60)));
        for consumed in 1..=5 {
            retry.observe(&failure("native_timeout", false), false, true);
            assert_eq!(retry.transient_failures, consumed);
            assert_eq!(retry.admission_attempt, 0);
            assert_eq!(retry.due.is_some(), consumed < 5);
            retry.observe(&applied(), false, false);
            assert_eq!(retry.transient_failures, consumed);
            assert_eq!(retry.due, None);
            retry.observe(&failure("readback", false), false, false); // rebuilt, not a supervisor retry
            assert_eq!(retry.transient_failures, consumed);
            assert_eq!(retry.due.is_some(), consumed < 5);
        }
        retry.observe(&refused(), false, true);
        assert_eq!(retry.transient_failures, 5);
        assert_eq!(delay(&retry), Some(Duration::from_secs(2)));
        retry.observe(&failure("blocks", false), false, true);
        assert_eq!(retry.transient_failures, 5);
        assert_eq!(retry.due, None);
    }

    #[tokio::test]
    async fn initial_refusal_keeps_live_listener_and_matching_retry_ensures_without_disable() {
        for protocol in [RestreamProtocol::Rtsp, RestreamProtocol::Srt] {
            let (manager, settings, policy) = listening(protocol, true).await;
            let (_, ctx) = manager.relay.supervisor().unwrap();
            let before = compute_status(&manager.state).await;
            assert!(before.server_running);
            assert!(matches!(before.firewall_next_retry_secs, Some(1 | 2)));
            let generation = manager
                .relay
                .state
                .lock()
                .await
                .restream_health
                .as_ref()
                .unwrap()
                .server_generation();
            assert_eq!(
                manager.relay.state.lock().await.firewall_generation,
                Some((generation, firewall_role(protocol)))
            );
            tokio::time::pause();
            {
                let mut state = manager.relay.state.lock().await;
                state.policy_retry.as_mut().unwrap().due =
                    Some(tokio::time::Instant::now() + Duration::from_millis(1001));
            }
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                Some(2)
            );
            tokio::time::advance(Duration::from_millis(1)).await;
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                Some(1)
            );
            tokio::time::advance(Duration::from_secs(1)).await;
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                Some(0)
            );
            let request = poll_policy_retry(&ctx).await.unwrap();
            retry_relay_policy(&ctx, request.0, request.1).await;
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                None
            );
            assert!(clean_firewall(
                &compute_status(&manager.state).await.firewall
            ));
            assert!(policy.disables.lock().unwrap().is_empty());
            let calls = policy.ensures.lock().unwrap().clone();
            assert_eq!(calls.len(), 2);
            assert_eq!(calls[0], calls[1]);
            assert_eq!(calls[1].0, firewall_role(protocol));
            assert_eq!(calls[1].1, resolved_spec_for_test(&settings).server_port());
            assert_eq!(calls[1].2.as_ref().unwrap().guid, "uplink");
            tokio::time::resume();
            manager.stop_restream_server().await.unwrap();
        }
    }

    #[tokio::test]
    async fn explicit_same_generation_refresh_does_not_replenish_exhausted_budget() {
        let (manager, settings, policy) = listening(RestreamProtocol::Rtsp, false).await;
        let (_, ctx) = manager.relay.supervisor().unwrap();
        for consumed in 1..=5 {
            policy
                .ensure_results
                .lock()
                .unwrap()
                .push_back(failure("readback", false));
            let (g, e) = due(&manager).await;
            retry_relay_policy(&ctx, g, e).await;
            let state = manager.relay.state.lock().await;
            let retry = state.policy_retry.as_ref().unwrap();
            assert_eq!(retry.transient_failures, consumed);
            assert_eq!(retry.due.is_some(), consumed < 5);
        }
        let generation = manager
            .relay
            .state
            .lock()
            .await
            .policy_retry
            .as_ref()
            .unwrap()
            .generation;
        let epoch = manager.relay.test_epoch();
        start(&manager.relay, &settings).await.unwrap();
        assert_eq!(manager.relay.test_epoch(), epoch + 1);
        assert_eq!(poll_policy_retry(&ctx).await, Some((generation, epoch + 1)));
        policy
            .ensure_results
            .lock()
            .unwrap()
            .push_back(failure("prepare", false));
        retry_relay_policy(&ctx, generation, epoch + 1).await;
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            None
        );
        assert_eq!(
            manager
                .relay
                .state
                .lock()
                .await
                .policy_retry
                .as_ref()
                .unwrap()
                .transient_failures,
            5
        );
        start(&manager.relay, &settings).await.unwrap();
        retry_relay_policy(&ctx, generation, manager.relay.test_epoch()).await;
        assert!(clean_firewall(
            &compute_status(&manager.state).await.firewall
        ));
        assert_eq!(
            manager
                .relay
                .state
                .lock()
                .await
                .policy_retry
                .as_ref()
                .unwrap()
                .transient_failures,
            5
        );
        assert_eq!(
            manager
                .relay
                .state
                .lock()
                .await
                .restream_server
                .as_ref()
                .unwrap()
                .server_generation(),
            generation
        );
        assert!(policy.disables.lock().unwrap().is_empty());
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn blocked_apply_retries_older_role_before_ensuring_desired_generation() {
        for result in [
            refused(),
            failure("disable", false),
            failure("native_timeout", false),
            failure("disable", true),
        ] {
            let bindings = Bindings::new(&[], vec![Read::ready(wildcard(1))]);
            let policy = Arc::new(Policy::default());
            policy
                .disable_results
                .lock()
                .unwrap()
                .push_back(result.clone());
            let (manager, settings) =
                fixture(RestreamProtocol::Rtsp, false, bindings, policy.clone());
            manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Srt));
            let (_, ctx) = manager.relay.supervisor().unwrap();
            assert_eq!(
                start(&manager.relay, &settings).await.unwrap().firewall,
                result.outcome
            );
            assert!(policy.ensures.lock().unwrap().is_empty());
            assert_eq!(
                manager.relay.state.lock().await.firewall_generation,
                Some((40, FirewallRule::Srt))
            );
            let snapshot = compute_status(&manager.state).await;
            assert!(snapshot.server_running);
            if matches!(
                result.outcome,
                FirewallOutcome::Failed {
                    uncertain: true,
                    ..
                }
            ) {
                assert_eq!(snapshot.firewall_next_retry_secs, None);
            } else {
                assert!(snapshot.firewall_next_retry_secs.is_some());
                let (g, e) = due(&manager).await;
                retry_relay_policy(&ctx, g, e).await;
                assert_eq!(
                    *policy.calls.lock().unwrap(),
                    [
                        ("disable", FirewallRule::Srt),
                        ("disable", FirewallRule::Srt),
                        ("ensure", FirewallRule::Rtsp)
                    ]
                );
                assert_eq!(
                    manager.relay.state.lock().await.firewall_generation,
                    Some((g, FirewallRule::Rtsp))
                );
                assert_eq!(
                    compute_status(&manager.state)
                        .await
                        .firewall_next_retry_secs,
                    None
                );
            }
            manager.stop_restream_server().await.unwrap();
        }
    }

    #[tokio::test]
    async fn identical_start_during_queued_or_admitted_retry_preserves_lease_and_coalesces() {
        for admitted in [false, true] {
            let (manager, settings, policy) = listening(RestreamProtocol::Rtsp, false).await;
            let (_, ctx) = manager.relay.supervisor().unwrap();
            let barrier = Arc::new(Barrier::default());
            if admitted {
                *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
            } else {
                *policy.admission_barrier.lock().unwrap() = Some(barrier.clone());
            }
            let (g, e) = due(&manager).await;
            let work = tokio::spawn({
                let ctx = ctx.clone();
                async move { retry_relay_policy(&ctx, g, e).await }
            });
            barrier.entered.notified().await;
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                Some(0)
            );
            start(&manager.relay, &settings).await.unwrap();
            start(&manager.relay, &settings).await.unwrap();
            assert_eq!(manager.relay.test_epoch(), e + 2);
            assert_eq!(
                manager
                    .relay
                    .state
                    .lock()
                    .await
                    .policy_retry
                    .as_ref()
                    .unwrap()
                    .generation,
                g
            );
            if admitted {
                assert!(!work.is_finished());
                barrier.release.notify_one();
            }
            work.await.unwrap();
            assert!(policy.disables.lock().unwrap().is_empty());
            assert_eq!(
                manager.relay.state.lock().await.firewall_generation,
                Some((g, FirewallRule::Rtsp))
            );
            if !admitted {
                assert_eq!(
                    compute_status(&manager.state).await.firewall,
                    refused().outcome
                );
                assert_eq!(
                    compute_status(&manager.state)
                        .await
                        .firewall_next_retry_secs,
                    Some(0)
                );
                // A stale handler must leave the current generation's due request alone.
                retry_relay_policy(&ctx, g, e).await;
                assert_eq!(policy.ensures.lock().unwrap().len(), 1);
                retry_relay_policy(&ctx, g, e + 2).await;
            }
            assert_eq!(policy.ensures.lock().unwrap().len(), 2);
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                None
            );
            manager.stop_restream_server().await.unwrap();
        }
    }

    #[tokio::test]
    async fn stop_during_scheduled_queued_and_admitted_retry_cannot_resurrect_or_hide_retirement_failure(
    ) {
        for phase in 0..3 {
            let (manager, _, policy) = listening(RestreamProtocol::Srt, false).await;
            let (_, ctx) = manager.relay.supervisor().unwrap();
            let (g, e) = due(&manager).await;
            let barrier = Arc::new(Barrier::default());
            let work = if phase > 0 {
                if phase == 1 {
                    *policy.admission_barrier.lock().unwrap() = Some(barrier.clone());
                } else {
                    *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
                }
                let work = tokio::spawn({
                    let ctx = ctx.clone();
                    async move { retry_relay_policy(&ctx, g, e).await }
                });
                barrier.entered.notified().await;
                Some(work)
            } else {
                None
            };
            let stop = manager.relay.begin_restream_stop_intent().await.unwrap();
            assert!(manager.relay.state.lock().await.policy_retry.is_none());
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                None
            );
            if phase == 2 {
                policy
                    .disable_results
                    .lock()
                    .unwrap()
                    .extend([failure("disable", true), failure("disable", true)]);
                assert!(!work.as_ref().unwrap().is_finished());
                barrier.release.notify_one();
            }
            if let Some(work) = work {
                work.await.unwrap();
            } else {
                retry_relay_policy(&ctx, g, e).await;
            }
            manager.relay.finish_restream_stop(stop).await.unwrap();
            assert_eq!(
                policy.ensures.lock().unwrap().len(),
                if phase == 2 { 2 } else { 1 }
            );
            let snapshot = compute_status(&manager.state).await;
            assert!(!snapshot.desired);
            assert!(!snapshot.server_running);
            assert_eq!(snapshot.firewall_next_retry_secs, None);
            assert_eq!(poll_policy_retry(&ctx).await, None);
            if phase == 2 {
                assert_eq!(snapshot.firewall, failure("disable", true).outcome);
                assert_eq!(
                    manager.relay.state.lock().await.firewall_generation,
                    Some((g, FirewallRule::Srt))
                );
            }
        }
    }

    #[tokio::test]
    async fn replacement_rejects_old_retry_dispatch_publication_and_schedule_changes() {
        for admitted in [false, true] {
            let (manager, settings, policy) = listening(RestreamProtocol::Rtsp, true).await;
            let (_, ctx) = manager.relay.supervisor().unwrap();
            let (g, e) = due(&manager).await;
            let barrier = Arc::new(Barrier::default());
            if admitted {
                *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
            } else {
                *policy.admission_barrier.lock().unwrap() = Some(barrier.clone());
            }
            let work = tokio::spawn({
                let ctx = ctx.clone();
                async move { retry_relay_policy(&ctx, g, e).await }
            });
            barrier.entered.notified().await;
            let mut replacement = settings.clone();
            replacement.rtsp_server.port = unused_tcp_port();
            let start = start(&manager.relay, &replacement);
            tokio::pin!(start);
            poll_pending(start.as_mut()).await;
            let (new_g, new_e) = due(&manager).await;
            assert_ne!(new_g, g);
            if admitted {
                barrier.release.notify_one();
            }
            work.await.unwrap();
            assert_eq!(
                manager
                    .relay
                    .state
                    .lock()
                    .await
                    .policy_retry
                    .as_ref()
                    .unwrap()
                    .generation,
                new_g
            );
            assert!(manager
                .relay
                .state
                .lock()
                .await
                .policy_retry
                .as_ref()
                .unwrap()
                .due
                .is_some());
            retry_relay_policy(&ctx, g, e).await;
            assert_eq!(manager.relay.test_epoch(), new_e);
            start.await.unwrap();
            assert_eq!(
                manager.relay.state.lock().await.firewall_generation,
                Some((new_g, FirewallRule::Rtsp))
            );
            assert!(clean_firewall(
                &compute_status(&manager.state).await.firewall
            ));
            assert_eq!(
                compute_status(&manager.state)
                    .await
                    .firewall_next_retry_secs,
                None
            );
            manager.stop_restream_server().await.unwrap();
        }
    }

    #[tokio::test]
    async fn explicit_refresh_includes_conflicts_and_terminal_failure_but_excludes_uncertainty() {
        let (manager, settings, policy) = listening(RestreamProtocol::Srt, false).await;
        let (_, ctx) = manager.relay.supervisor().unwrap();
        let g = manager
            .relay
            .state
            .lock()
            .await
            .policy_retry
            .as_ref()
            .unwrap()
            .generation;
        let mut conflicts = applied().outcome;
        if let FirewallOutcome::Applied {
            observed_block_rules,
            ..
        } = &mut conflicts
        {
            observed_block_rules.push("disabled other-protocol rule".into());
        }
        let mut unverified = applied().outcome;
        if let FirewallOutcome::Applied { verified_shape, .. } = &mut unverified {
            *verified_shape = false;
        }
        for outcome in [
            conflicts,
            unverified,
            failure("ownership", false).outcome,
            PolicyResult::accepted(FirewallOutcome::Unavailable {
                reason: "Administrator access required".into(),
            })
            .outcome,
            FirewallOutcome::Inactive,
            failure("native_timeout", true).outcome,
            applied().outcome,
        ] {
            {
                let mut state = manager.relay.state.lock().await;
                state.firewall = outcome.clone();
                state.policy_retry.as_mut().unwrap().due = None;
            }
            let before = policy.ensures.lock().unwrap().len();
            let reply = start(&manager.relay, &settings).await.unwrap();
            assert_eq!(reply.firewall, outcome);
            assert_eq!(
                policy.ensures.lock().unwrap().len(),
                before,
                "Start requests a supervisor attempt, not native success"
            );
            let eligible = !clean_firewall(&outcome)
                && !matches!(
                    outcome,
                    FirewallOutcome::Failed {
                        uncertain: true,
                        ..
                    }
                );
            assert_eq!(poll_policy_retry(&ctx).await.is_some(), eligible);
            if eligible {
                retry_relay_policy(&ctx, g, manager.relay.test_epoch()).await;
            }
            assert_eq!(
                manager
                    .relay
                    .state
                    .lock()
                    .await
                    .policy_retry
                    .as_ref()
                    .unwrap()
                    .generation,
                g
            );
        }
        assert!(policy.disables.lock().unwrap().is_empty());
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn recovery_dead_listener_and_mismatched_generation_are_ineligible() {
        let (manager, _, policy) = listening(RestreamProtocol::Rtsp, true).await;
        let (_, ctx) = manager.relay.supervisor().unwrap();
        let (g, e) = due(&manager).await;
        {
            let mut state = manager.relay.state.lock().await;
            state.policy_retry.as_mut().unwrap().generation = g + 1;
        }
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            None
        );
        assert_eq!(poll_policy_retry(&ctx).await, None);
        {
            let mut state = manager.relay.state.lock().await;
            state.policy_retry.as_mut().unwrap().generation = g;
            state
                .restream_health
                .as_ref()
                .unwrap()
                .mark_recovery_in_progress();
        }
        retry_relay_policy(&ctx, g, e).await;
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            None
        );
        assert_eq!(policy.ensures.lock().unwrap().len(), 1);
        assert!(
            record_bind_failure(
                &manager.relay.state,
                &manager.relay.restream_epoch,
                e,
                g,
                "binding observation failed".into(),
                None
            )
            .await
        );
        assert!(manager
            .relay
            .state
            .lock()
            .await
            .policy_retry
            .as_ref()
            .unwrap()
            .due
            .is_none());
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn one_second_supervisor_services_due_retry_and_keeps_zero_through_admitted_work() {
        let (manager, _, policy) = listening(RestreamProtocol::Rtsp, true).await;
        let (events, ctx) = manager.relay.supervisor().unwrap();
        due(&manager).await;
        let barrier = Arc::new(Barrier::default());
        *policy.ensure_barrier.lock().unwrap() = Some(barrier.clone());
        let mut status = manager.status.subscribe();
        tokio::time::pause();
        let supervisor = tokio::spawn(run_relay_supervisor(events, ctx));
        barrier.entered.notified().await;
        assert_eq!(status.borrow().firewall_next_retry_secs, Some(0));
        barrier.release.notify_one();
        while !clean_firewall(&status.borrow().firewall) {
            status.changed().await.unwrap();
        }
        assert_eq!(status.borrow().firewall_next_retry_secs, None);
        assert_eq!(policy.ensures.lock().unwrap().len(), 2);
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        tokio::time::resume();
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn fault_has_priority_over_due_retry_and_recovery_clears_the_schedule() {
        let (manager, _, policy) = listening(RestreamProtocol::Rtsp, true).await;
        let (events, ctx) = manager.relay.supervisor().unwrap();
        due(&manager).await;
        let health = manager
            .relay
            .state
            .lock()
            .await
            .restream_health
            .clone()
            .unwrap();
        let instance = health.snapshot().server_instance;
        let data = health.begin_data_generation(instance).unwrap();
        let fault = health
            .report_fault(
                instance,
                data,
                relay::RelayFaultKind::GstError,
                "injected fault".into(),
            )
            .unwrap();
        ctx.relay_event_tx
            .send(RelaySupervisorEvent::Fault(fault))
            .unwrap();
        let barrier = Arc::new(Barrier::default());
        *policy.disable_barrier.lock().unwrap() = Some(barrier.clone());
        let supervisor = tokio::spawn(run_relay_supervisor(events, ctx));
        barrier.entered.notified().await;
        assert_eq!(policy.ensures.lock().unwrap().len(), 1);
        assert!(manager
            .relay
            .state
            .lock()
            .await
            .policy_retry
            .as_ref()
            .unwrap()
            .due
            .is_none());
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            None
        );
        let stop = manager.relay.begin_restream_stop_intent().await.unwrap();
        barrier.release.notify_one();
        manager.relay.finish_restream_stop(stop).await.unwrap();
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        assert_eq!(policy.ensures.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn prior_retirement_does_not_abort_but_epoch_is_rechecked_before_ensure() {
        let (manager, settings, policy) = listening(RestreamProtocol::Rtsp, true).await;
        let (_, ctx) = manager.relay.supervisor().unwrap();
        manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Srt));
        let (g, e) = due(&manager).await;
        let barrier = Arc::new(Barrier::default());
        *policy.disable_barrier.lock().unwrap() = Some(barrier.clone());
        let work = tokio::spawn({
            let ctx = ctx.clone();
            async move { retry_relay_policy(&ctx, g, e).await }
        });
        barrier.entered.notified().await;
        start(&manager.relay, &settings).await.unwrap();
        assert!(!work.is_finished());
        barrier.release.notify_one();
        work.await.unwrap();
        assert_eq!(policy.ensures.lock().unwrap().len(), 1);
        assert!(manager
            .relay
            .state
            .lock()
            .await
            .firewall_generation
            .is_none());
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            Some(0)
        );
        retry_relay_policy(&ctx, g, manager.relay.test_epoch()).await;
        assert_eq!(policy.ensures.lock().unwrap().len(), 2);
        assert_eq!(*policy.disables.lock().unwrap(), [FirewallRule::Srt]);
        manager.stop_restream_server().await.unwrap();
    }

    #[tokio::test]
    async fn further_replacement_retains_older_lease_and_stops_retrying_uncertainty() {
        let (manager, mut settings, policy) = listening(RestreamProtocol::Rtsp, true).await;
        let (_, ctx) = manager.relay.supervisor().unwrap();
        let (g, e) = due(&manager).await;
        manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Srt));
        policy
            .disable_results
            .lock()
            .unwrap()
            .extend([failure("disable", true), failure("disable", true)]);
        settings.rtsp_server.port = unused_tcp_port();
        let reply = start(&manager.relay, &settings).await.unwrap();
        assert_eq!(reply.firewall, failure("disable", true).outcome);
        let new_g = manager
            .relay
            .state
            .lock()
            .await
            .policy_retry
            .as_ref()
            .unwrap()
            .generation;
        assert_ne!(new_g, g);
        retry_relay_policy(&ctx, g, e).await;
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((40, FirewallRule::Srt))
        );
        assert_eq!(
            manager
                .relay
                .state
                .lock()
                .await
                .policy_retry
                .as_ref()
                .unwrap()
                .generation,
            new_g
        );
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            None
        );
        manager.stop_restream_server().await.unwrap();
        assert_eq!(
            manager.relay.state.lock().await.firewall_generation,
            Some((40, FirewallRule::Srt))
        );
        assert_eq!(
            compute_status(&manager.state).await.firewall,
            failure("disable", true).outcome
        );
    }

    // Capture only this current-thread test's relay outcomes, so ordinary
    // parallel tests neither serialize nor contaminate the assertions.
    thread_local! {
        static POLICY_LOGS: std::cell::RefCell<Option<Vec<(log::Level, String)>>> = const { std::cell::RefCell::new(None) };
    }
    struct PolicyLog;
    impl log::Log for PolicyLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            POLICY_LOGS.with(|slot| {
                if let Some(lines) = slot.borrow_mut().as_mut() {
                    let text = record.args().to_string();
                    if text.starts_with("event=relay_firewall ") {
                        lines.push((record.level(), text));
                    }
                }
            });
        }
        fn flush(&self) {}
    }
    fn capture_policy_logs() {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(|| {
            log::set_logger(&PolicyLog).unwrap();
            log::set_max_level(log::LevelFilter::Info);
        });
        POLICY_LOGS.with(|slot| *slot.borrow_mut() = Some(vec![]));
    }
    fn take_policy_logs() -> Vec<(log::Level, String)> {
        POLICY_LOGS.with(|slot| slot.borrow_mut().take().unwrap())
    }

    struct RestoreLogFilter(log::LevelFilter);
    impl Drop for RestoreLogFilter {
        fn drop(&mut self) {
            log::set_max_level(self.0);
        }
    }

    #[tokio::test]
    async fn relay_logs_each_actual_result_once_including_blocked_apply_and_redacted_rebuild() {
        let _log_filter = RestoreLogFilter(log::max_level());
        let (manager, _, policy) = listening(RestreamProtocol::Rtsp, true).await;
        let (_, ctx) = manager.relay.supervisor().unwrap();
        manager.relay.state.lock().await.firewall_generation = Some((40, FirewallRule::Srt));
        policy.disable_results.lock().unwrap().push_back(refused());
        capture_policy_logs();
        let (g, e) = due(&manager).await;
        retry_relay_policy(&ctx, g, e).await;
        let lines = take_policy_logs();
        assert_eq!(
            lines.len(),
            1,
            "failed prior retirement is not a fictitious Ensure"
        );
        assert!(lines[0]
            .1
            .contains("phase=retire generation=40 role=srt admitted=false outcome=unavailable"));
        assert!(lines[0]
            .1
            .contains(&format!("retry_for_generation={g} next_retry_ms=")));
        assert_eq!(lines[0].0, log::Level::Warn);
        capture_policy_logs();
        let (g, e) = due(&manager).await;
        retry_relay_policy(&ctx, g, e).await;
        let lines = take_policy_logs();
        assert_eq!(lines.len(), 2);
        assert!(lines[0]
            .1
            .contains("phase=retire generation=40 role=srt admitted=true outcome=inactive"));
        assert!(lines[1].1.contains("phase=retry"));
        assert_eq!(lines[1].0, log::Level::Info);
        let mut conflict = applied();
        if let FirewallOutcome::Applied {
            observed_block_rules,
            ..
        } = &mut conflict.outcome
        {
            *observed_block_rules = vec![
                "private full native Block name".into(),
                "disabled unrelated Block name".into(),
            ];
        }
        policy.ensure_results.lock().unwrap().push_back(conflict);
        capture_policy_logs();
        let (g, e) = due(&manager).await;
        retry_relay_policy(&ctx, g, e).await;
        let lines = take_policy_logs();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].0, log::Level::Warn);
        assert!(lines[0].1.contains("verified=true blocks=2"));
        assert!(!lines[0].1.contains("full native Block"));
        assert_eq!(
            compute_status(&manager.state)
                .await
                .firewall_next_retry_secs,
            None
        );
        capture_policy_logs();
        assert!(retire_firewall(&manager.relay.state, policy.as_ref(), 99).await);
        assert!(
            take_policy_logs().is_empty(),
            "idempotent absence has no policy result"
        );
        {
            let mut state = manager.relay.state.lock().await;
            state.policy_retry.as_mut().unwrap().transient_failures = 3;
            let spec = state.restream_spec.as_mut().unwrap();
            spec.username = "private-camera-user".into();
            spec.password = "private-camera-password".into();
            state
                .restream_health
                .as_ref()
                .unwrap()
                .mark_recovery_in_progress();
        }
        let mut result = failure("native_timeout", false);
        if let FirewallOutcome::Failed { reason, .. } = &mut result.outcome {
            *reason = format!(
                "rtsp://private-camera-user:private-camera-password@192.0.2.2 {}\nreason={}next",
                manager
                    .relay
                    .state
                    .lock()
                    .await
                    .restream_spec
                    .as_ref()
                    .unwrap()
                    .mount_path(),
                "x".repeat(500)
            );
        }
        policy.ensure_results.lock().unwrap().push_back(result);
        capture_policy_logs();
        recover_relay_generation(&ctx, e, g, "test_fault").await;
        let lines = take_policy_logs();
        assert_eq!(lines.len(), 2, "one retirement and one rebuild result");
        assert!(lines[1].1.contains("phase=rebuild"));
        assert!(lines[1].1.contains("uncertain=false"));
        assert!(lines[1].1.contains("next_retry_ms="));
        assert!(!lines[1].1.contains("private-camera"));
        assert!(!lines[1].1.contains("0123456789abcdef"));
        assert!(!lines[1].1.contains('\n'));
        assert!(lines[1].1.len() < 650);
        let state = manager.relay.state.lock().await;
        assert_eq!(state.policy_retry.as_ref().unwrap().transient_failures, 3);
        assert!(state.policy_retry.as_ref().unwrap().due.is_some());
        drop(state);
        assert!(compute_status(&manager.state).await.server_running);
        manager.stop_restream_server().await.unwrap();
    }
}
