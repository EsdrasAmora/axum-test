use anyhow;
use axum::{
    extract::Path,
    handler::Handler,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::get,
    Extension, Json, Router,
};
use dotenv::{dotenv, var};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{postgres::PgPoolOptions, PgPool};
use std::{net::SocketAddr, time::Duration};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenv().ok();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "debug".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let pool = PgPoolOptions::new()
        .max_connections(10)
        .idle_timeout(Duration::from_secs(3))
        .connect(&var("DATABASE_URL")?)
        .await?;

    let app = Router::new()
        .route("/", get(root))
        .route("/todos", get(list_todos).post(add_todo))
        .route(
            "/todos/:id",
            get(find_todo).put(update_todo).delete(delete_todo),
        )
        .fallback(handler_404.into_service())
        .layer(TraceLayer::new_for_http())
        .layer(Extension(pool));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    tracing::info!("listening on {}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn root() -> &'static str {
    "Hello, World!"
}

async fn handler_404() -> impl IntoResponse {
    (StatusCode::NOT_FOUND, "nothing to see here")
}

enum AppError {
    InternalServerError(anyhow::Error),
    ValidationError,
}

impl From<anyhow::Error> for AppError {
    fn from(inner: anyhow::Error) -> Self {
        AppError::InternalServerError(inner)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, error_message) = match self {
            AppError::InternalServerError(inner) => {
                tracing::debug!("stacktrace: {}", inner);
                (StatusCode::INTERNAL_SERVER_ERROR, "something went wrong")
            }
            AppError::ValidationError => (StatusCode::BAD_REQUEST, "validation errors"),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct Todo {
    id: i64,
    description: String,
    done: bool,
}

#[derive(Deserialize)]
struct CreateTodo {
    description: String,
}

#[derive(Deserialize)]
struct UpdateTodo {
    description: Option<String>,
    done: Option<bool>,
}

async fn add_todo(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<CreateTodo>,
) -> Result<String, AppError> {
    let rec = sqlx::query_as!(
        Todo,
        r#"
            INSERT INTO todos ( description )
            VALUES ( $1 )
            RETURNING *
        "#,
        payload.description,
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| anyhow::Error::from(e))?;

    Ok(rec.id.to_string())
}

async fn delete_todo(
    Extension(pool): Extension<PgPool>,
    Path(id): Path<i64>,
) -> Result<String, AppError> {
    sqlx::query_as!(
        Todo,
        r#"
            DELETE FROM todos WHERE id = $1
        "#,
        id,
    )
    .execute(&pool)
    .await
    .map_err(|e| anyhow::Error::from(e))?;

    Ok(true.to_string())
}

async fn update_todo(
    Extension(pool): Extension<PgPool>,
    Json(payload): Json<UpdateTodo>,
    Path(id): Path<i64>,
) -> Result<Json<Todo>, AppError> {
    if payload.description.is_none() && payload.done.is_none() {
        return Err(AppError::ValidationError);
    }

    let todo = sqlx::query_as!(
        Todo,
        r#"
            UPDATE
                todos
            SET
                description = COALESCE($1, description),
                done = COALESCE($2, done)
            WHERE
                (description <> $1 OR done <> $2) 
                AND id = $3
            RETURNING *
        "#,
        payload.description,
        payload.done,
        id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| anyhow::Error::from(e))?;

    Ok(Json(todo))
}

async fn find_todo(
    Extension(pool): Extension<PgPool>,
    Path(id): Path<i64>,
) -> Result<Json<Todo>, AppError> {
    let todo = sqlx::query_as!(
        Todo,
        r#"
            SELECT * FROM todos WHERE id = $1
        "#,
        id
    )
    .fetch_one(&pool)
    .await
    .map_err(|e| anyhow::Error::from(e))?;

    Ok(Json(todo))
}

async fn list_todos(Extension(pool): Extension<PgPool>) -> Result<Json<Vec<Todo>>, AppError> {
    let recs = sqlx::query_as!(
        Todo,
        r#"
            SELECT id, description, done
            FROM todos
            ORDER BY id
        "#
    )
    .fetch_all(&pool)
    .await
    .map_err(|e| anyhow::Error::from(e))?;

    Ok(Json(recs))
}

// #[derive(Deserialize)]
// struct CreateUser {
//     username: String,
// }

// #[derive(Debug, Serialize, Deserialize, Clone, Eq, Hash, PartialEq)]
// struct User {
//     id: u64,
//     username: String,
// }

// async fn create_user(payload: Json<CreateUser>) -> impl IntoResponse {
//     let user = User {
//         id: 1337,
//         username: payload.0.username,
//     };

//     (StatusCode::CREATED, Json(user))
// }

// async fn json_hello(Path(name): Path<String>) -> impl IntoResponse {
//     let greeting = name.as_str();
//     let hello = String::from("Hello ");

//     (
//         StatusCode::OK,
//         [("foo", "bar")],
//         Json(json!({ "message": hello + greeting })),
//     )
// }
