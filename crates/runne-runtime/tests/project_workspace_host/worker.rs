use super::worker_support::{blocked_host, poll_once};
use super::*;
use runne_runtime::PROJECT_WORKSPACE_WORKER_CAPACITY;
use std::{task::Poll, time::Duration};

#[tokio::test]
async fn saturated_worker_returns_backpressure_and_never_blocks_tokio() {
    let (_directory, host, entered, gate) = blocked_host();
    let owner = principal("owner");
    let mut blocker = Box::pin(host.create_project(
        context(owner.clone(), &command_id(80), "worker-blocker"),
        CreateProjectCommand {
            project_id: project_id(80),
            display_name: name("Blocker"),
        },
    ));
    assert!(poll_once(blocker.as_mut()).is_pending());
    entered.await.unwrap();

    tokio::time::timeout(
        Duration::from_secs(1),
        tokio::time::sleep(Duration::from_millis(1)),
    )
    .await
    .expect("Tokio timer must run while the synchronous repository is blocked");

    let mut queued = Vec::with_capacity(PROJECT_WORKSPACE_WORKER_CAPACITY);
    for tail in 0..PROJECT_WORKSPACE_WORKER_CAPACITY {
        let mut query = Box::pin(host.get_project(
            ProjectQueryContext {
                principal: owner.clone(),
            },
            project_id(100 + tail as u8),
        ));
        assert!(poll_once(query.as_mut()).is_pending());
        queued.push(query);
    }
    let mut overflow =
        Box::pin(host.get_project(ProjectQueryContext { principal: owner }, project_id(0xfe)));
    assert_eq!(
        poll_once(overflow.as_mut()),
        Poll::Ready(Err(ProjectWorkspaceHostError::Backpressure))
    );

    gate.release();
    assert_eq!(blocker.await.unwrap().new_version, 1);
    for query in queued {
        assert_eq!(query.await.err(), Some(ProjectWorkspaceHostError::NotFound));
    }
}

#[tokio::test]
async fn shutdown_closes_pending_replies_and_future_command_and_query_calls() {
    let (_directory, host, entered, gate) = blocked_host();
    let owner = principal("owner");
    let mut blocker = Box::pin(host.create_project(
        context(owner.clone(), &command_id(81), "shutdown-blocker"),
        CreateProjectCommand {
            project_id: project_id(81),
            display_name: name("Blocker"),
        },
    ));
    assert!(poll_once(blocker.as_mut()).is_pending());
    entered.await.unwrap();

    let mut shutdown = Box::pin(host.shutdown());
    assert!(poll_once(shutdown.as_mut()).is_pending());
    let mut pending_command = Box::pin(host.create_project(
        context(owner.clone(), &command_id(82), "pending-command"),
        CreateProjectCommand {
            project_id: project_id(82),
            display_name: name("Pending"),
        },
    ));
    assert!(poll_once(pending_command.as_mut()).is_pending());
    let mut pending_query = Box::pin(host.get_project(
        ProjectQueryContext {
            principal: owner.clone(),
        },
        project_id(82),
    ));
    assert!(poll_once(pending_query.as_mut()).is_pending());

    gate.release();
    blocker.await.unwrap();
    shutdown.await;
    assert_eq!(
        pending_command.await.err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
    assert_eq!(
        pending_query.await.err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
    assert_eq!(
        host.create_project(
            context(owner.clone(), &command_id(83), "after-shutdown"),
            CreateProjectCommand {
                project_id: project_id(83),
                display_name: name("Closed")
            },
        )
        .await
        .err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
    assert_eq!(
        host.get_project(ProjectQueryContext { principal: owner }, project_id(83))
            .await
            .err(),
        Some(ProjectWorkspaceHostError::Unavailable)
    );
}
