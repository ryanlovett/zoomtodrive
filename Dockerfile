FROM ubuntu:20.04

ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV PATH /opt/conda/bin:$PATH

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=US/Pacific

RUN apt-get update --fix-missing && \
    apt-get -y install \
        bzip2 \
        ca-certificates \
        curl \
        git \
        wget \
        vim-tiny

# https://github.com/ContinuumIO/docker-images/blob/master/miniconda3/debian/Dockerfile
ENV MINICONDA_VERSION=py38_4.8.3
RUN wget --quiet https://repo.anaconda.com/miniconda/Miniconda3-${MINICONDA_VERSION}-Linux-x86_64.sh -O ~/miniconda.sh && \
    /bin/bash ~/miniconda.sh -b -p /opt/conda && \
    rm ~/miniconda.sh && \
    /opt/conda/bin/conda clean -tipsy && \
    ln -s /opt/conda/etc/profile.d/conda.sh /etc/profile.d/conda.sh && \
    echo ". /opt/conda/etc/profile.d/conda.sh" >> ~/.bashrc && \
    echo "conda activate base" >> ~/.bashrc && \
    find /opt/conda/ -follow -type f -name '*.a' -delete && \
    find /opt/conda/ -follow -type f -name '*.js.map' -delete && \
    /opt/conda/bin/conda clean -afy

RUN conda config --add channels conda-forge
RUN conda config --set channel_priority strict

WORKDIR /srv/zoomtodrive/

ADD requirements.txt /tmp/

RUN conda install \
    conda=4.9.0 \
    mamba=0.5.1
RUN mamba install -y uwsgi=2.0.18
RUN pip3 install -r /tmp/requirements.txt

RUN useradd --create-home uwsgi

ADD . /srv/zoomtodrive/

EXPOSE 9090
EXPOSE 5000

CMD ["uwsgi", "uwsgi.ini"]
