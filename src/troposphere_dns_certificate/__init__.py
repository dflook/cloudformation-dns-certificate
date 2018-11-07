import wrapt


class TroposphereExtension:
    def add_extension(self, template, add_resource):
        """
        Add this resource to the template

        This will be called on extension resources.
        The implementation should add standard troposphere resources to the template

        :param template: The template to add this resource to
        :param add_resource: The add_resource function to call to add resources
        """
        raise NotImplementedError('This method should add standard troposphere resources to the template')


@wrapt.patch_function_wrapper('troposphere', 'Template.add_resource')
def wrapper(wrapped, instance, args, kwargs):
    def get_resource(resource):
        return resource

    resource = get_resource(*args, **kwargs)

    if isinstance(resource, TroposphereExtension):
        return resource.add_extension(instance, wrapped)

    return wrapped(*args, **kwargs)
