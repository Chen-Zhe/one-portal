from flask import Flask, render_template
app = Flask(__name__)

@app.route("/")
def hello():
    return render_template("test.html",data="hello world")

if __name__ == "__main__":
    app.run()