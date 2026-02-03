use super::{ObjectId, ObjectType, Store};
use navigator_core::proto::ObjectForTest;

#[tokio::test]
async fn sqlite_put_get_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store.put("sandbox", "abc", b"payload").await.unwrap();

    let record = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert_eq!(record.object_type, "sandbox");
    assert_eq!(record.id, "abc");
    assert_eq!(record.payload, b"payload");
}

#[tokio::test]
async fn sqlite_updates_timestamp() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store.put("sandbox", "abc", b"payload").await.unwrap();

    let first = store.get("sandbox", "abc").await.unwrap().unwrap();

    store.put("sandbox", "abc", b"payload2").await.unwrap();

    let second = store.get("sandbox", "abc").await.unwrap().unwrap();
    assert!(second.updated_at_ms >= first.updated_at_ms);
    assert_eq!(second.payload, b"payload2");
}

#[tokio::test]
async fn sqlite_list_paging() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    for idx in 0..5 {
        let id = format!("id-{idx}");
        let payload = format!("payload-{idx}");
        store.put("sandbox", &id, payload.as_bytes()).await.unwrap();
    }

    let records = store.list("sandbox", 2, 1).await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].id, "id-1");
    assert_eq!(records[1].id, "id-2");
}

#[tokio::test]
async fn sqlite_delete_behavior() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    store.put("sandbox", "abc", b"payload").await.unwrap();

    let deleted = store.delete("sandbox", "abc").await.unwrap();
    assert!(deleted);

    let deleted_again = store.delete("sandbox", "missing").await.unwrap();
    assert!(!deleted_again);
}

#[tokio::test]
async fn sqlite_protobuf_round_trip() {
    let store = Store::connect("sqlite::memory:?cache=shared")
        .await
        .unwrap();

    let object = ObjectForTest {
        id: "abc".to_string(),
        name: "sandbox".to_string(),
        count: 42,
    };

    store.put_message(&object).await.unwrap();

    let loaded = store
        .get_message::<ObjectForTest>(&object.id)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(loaded.id, object.id);
    assert_eq!(loaded.name, object.name);
    assert_eq!(loaded.count, object.count);
}

impl ObjectType for ObjectForTest {
    fn object_type() -> &'static str {
        "object_for_test"
    }
}

impl ObjectId for ObjectForTest {
    fn object_id(&self) -> &str {
        &self.id
    }
}
