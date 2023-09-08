use app_prover::App;
use std::sync::Arc;

fn main() {
    glog::init();
    let app = Arc::new(App::default());
    apps::set_ctrlc({
        let app = app.clone();
        move || {
            apps::App::terminate(app.as_ref());
        }
    });
    apps::run_std(app.as_ref());
}
