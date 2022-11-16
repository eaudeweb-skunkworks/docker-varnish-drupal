# docker-varnish-drupal
Varnish Docker with support for Drupal 8+


# Build & run locally

```shell
# ./build.sh
# docker run -it --rm --name varnish-d8 -e cristiroma/varnish-drupal:d8
```


# Usage in docker-compose.yml

```YAML

services:

  cache:
    image: cristiroma/varnish-drupal:d8
    container_name: project_prod_varnish
    restart: unless-stopped
    env_file: .app.env
    depends_on:
     - app
    # Custom config for Drupal Cache-Tag long headers
    command: "-p http_max_hdr=512 -p http_resp_hdr_len=1024768 -p http_resp_size=3024768 -p thread_pool_min=200 -p thread_pool_max=500 -p http_req_size=64000"
    ports:
     - 127.0.0.1:6082:80
```
