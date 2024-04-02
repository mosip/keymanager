FROM openjdk:11

ARG SOURCE
ARG COMMIT_HASH
ARG COMMIT_ID
ARG BUILD_TIME

LABEL source=${SOURCE}
LABEL commit_hash=${COMMIT_HASH}
LABEL commit_id=${COMMIT_ID}
LABEL build_time=${BUILD_TIME}

RUN apt-get update \
    && apt-get -y upgrade \
    && apt-get -y install unzip

ARG spring_config_label
ARG active_profile
ARG spring_config_url
ARG artifactory_url
ARG spring_config_name
ARG hsm_client_zip_path

ARG hsm_local_dir=hsm-client
ENV hsm_local_dir_name=${hsm_local_dir}

ENV active_profile_env=${active_profile}
ENV spring_config_label_env=${spring_config_label}
ENV spring_config_url_env=${spring_config_url}
ENV spring_config_name_env=${spring_config_name}
ENV artifactory_url_env=${artifactory_url}
ENV hsm_zip_file_path=${hsm_client_zip_path}

ENV work_dir=/
ARG loader_path=${work_dir}/additional_jars/
RUN mkdir -p ${loader_path}
ENV loader_path_env=${loader_path}

ADD configure_start.sh configure_start.sh
RUN chmod +x configure_start.sh
ADD target/keys-migrator-*.jar keys-migrator.jar

ENTRYPOINT [ "/configure_start.sh" ]
CMD ["java","-jar", "-Dloader.path=${loader_path_env}", "-Dspring.cloud.config.label=${spring_config_label_env}","-Dspring.cloud.config.name=${spring_config_name_env}", "-Dspring.profiles.active=${active_profile_env}", "-Dspring.cloud.config.uri=${spring_config_url_env}", "/keys-migrator.jar"]

ARG container_user=mosip
ARG container_user_group=mosip
ARG container_user_uid=1001
ARG container_user_gid=1001

WORKDIR /home/${container_user}

RUN chown -R ${container_user}:${container_user} /home/${container_user}

USER ${container_user_uid}:${container_user_gid}
