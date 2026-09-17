package org.springframework.gradle.maven;

import org.gradle.api.Plugin;
import org.gradle.api.Project;
import org.gradle.api.publish.PublishingExtension;
import org.gradle.api.publish.maven.plugins.MavenPublishPlugin;
import org.springframework.gradle.maven.MavenRepositorySettingsPlugin.MavenRepositorySettings;

public class PublishRemotePlugin implements Plugin<Project> {

	@Override
	public void apply(Project project) {
		Project rootProject = project.getRootProject();
		MavenRepositorySettings settings = rootProject.getExtensions().findByType(MavenRepositorySettings.class);

		if (settings == null) {
			return;
		}

		project.getPlugins().withType(MavenPublishPlugin.class).all(mavenPublish -> {
			PublishingExtension publishing = project.getExtensions().getByType(PublishingExtension.class);
			publishing.getRepositories().maven(maven -> {
				maven.setName("remote");
				maven.setUrl(settings.getUrl());
				maven.credentials(credentials -> {
					credentials.setUsername(settings.getUsername());
					credentials.setPassword(settings.getPassword());
				});
			});
		});
	}
}
