from flask import Blueprint, render_template, flash, url_for, redirect
from flask_login import current_user, login_required

from config import db, Post
from posts.forms import PostForm
from sqlalchemy import desc
from flask import Blueprint, render_template, flash, redirect, url_for
from accounts.forms import RegistrationForm
from config import User, db
posts_bp = Blueprint('posts', __name__, template_folder='templates')

@posts_bp.route('/create', methods=('GET', 'POST'))
@login_required
def create():

    form = PostForm()

    if form.validate_on_submit():
        new_post = Post(title=form.title.data, body=form.body.data)
        new_post.user = current_user

        db.session.add(new_post)
        db.session.commit()
        flash('Post created', category='success')

        return redirect(url_for('posts.posts'))

    return render_template('posts/create.html', form=form)

@posts_bp.route('/posts')
@login_required
def posts():
    all_posts = Post.query.order_by(desc('id')).all()
    return render_template('posts/posts.html', posts=all_posts)

@posts_bp.route('/<int:id>/update', methods=('GET', 'POST'))
@login_required
def update(id):
    post_to_update = Post.query.filter_by(id=id).first()

    if not post_to_update or post_to_update.user_id != current_user.id:
        flash("You cannot update this post.", "danger")
        return redirect(url_for('posts.posts'))

    form = PostForm()

    if form.validate_on_submit():
        post_to_update.title = form.title.data
        post_to_update.body = form.body.data
        db.session.commit()

        flash('Post updated', category='success')
        return redirect(url_for('posts.posts'))

    form.title.data = post_to_update.title
    form.body.data = post_to_update.body

    return render_template('posts/update.html', form=form, post=post_to_update)


@posts_bp.route('/<int:id>/delete')
@login_required
def delete(id):
    post_to_delete = Post.query.filter_by(id=id, user_id=current_user.id).first()

    if not post_to_delete:
        flash("You cannot delete this post.", "danger")
        return redirect(url_for('posts.posts'))

    db.session.delete(post_to_delete)
    db.session.commit()

    flash('Post deleted', category='success')
    return redirect(url_for('posts.posts'))